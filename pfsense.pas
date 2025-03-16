unit PfSense;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fphttpclient, fpjson, jsonparser,
  Forms, Controls, Graphics, Dialogs, Variants,
  fgl, openapipf.api, base64, StdCtrls;

type
  TClientSchedule = class
  public
    ClientName: string;
    IPAddress: string;
    AccessStartTime: TTime;
    AccessEndTime: TTime;
    RuleDescription: string;
  end;

  { Тип списка клиентских расписаний }
  TClientScheduleList = specialize TFPGList<TClientSchedule>;

  TPfSense = class(TComponent)
  private
    FBaseURL: string;
    FBaseURLRoot: string;
    FUsername: string;
    FPassword: string;
    FOpenSSL: Boolean;
    FToken: string;
    FLastResponse: string;
    FLogFileName: string;
    FHttp: TFPHTTPClient;
    FApiClient: TOpenapipfClient;
    FClientSchedules: TClientScheduleList;
    FAllowedFirewallFields: TStrings;
    FMaxFirewallResults: Integer;
    FUseBasicAuth: Boolean;
    FDebugMemo: TMemo;
    procedure SetBaseURL(AValue: string);
    procedure SetBaseURLRoot(AValue: string);
    procedure SetUsername(AValue: string);
    procedure SetPassword(AValue: string);
    procedure SetOpenSSL(AValue: Boolean);
    procedure SetLogFileName(AValue: string);
    procedure SetAllowedFirewallFields(Value: TStrings);
    procedure SetMaxFirewallResults(AValue: Integer);
    procedure WriteLog(const Message: string);
    function FilterFirewallJson(const JsonStr: string): string;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    function GetVersion: string;
    function GetFirewallRules: string;
    function GetFirewallRule(const RuleID: string): string;
    function DeleteFirewallRule(const RuleID: string): string;
    procedure ApplyChanges;
    function GetLastResponse: string;
    procedure AddClientSchedule(ClientName, IPAddress: string;
      AccessStartTime, AccessEndTime: TTime; RuleDescription: string);
    function GetClientSchedules: TClientScheduleList;
    procedure AddAuthHeader(aHTTP: TFPHTTPClient);
    // Метод для получения временного диапазона расписания
    function GetScheduleTimeRange(const ParentID, TimeRangeID: string): string;
    property BaseURL: string read FBaseURL write SetBaseURL;
    property BaseURLRoot: string read FBaseURLRoot write SetBaseURLRoot;
    property Username: string read FUsername write SetUsername;
    property Password: string read FPassword write SetPassword;
    property OpenSSL: Boolean read FOpenSSL write SetOpenSSL default True;
    property LastResponse: string read FLastResponse write FLastResponse;
    property LogFileName: string read FLogFileName write SetLogFileName;
    property AllowedFirewallFields: TStrings read FAllowedFirewallFields write SetAllowedFirewallFields;
    property MaxFirewallResults: Integer read FMaxFirewallResults write SetMaxFirewallResults default 0;
    property Token: string read FToken write FToken;
    property UseBasicAuth: Boolean read FUseBasicAuth write FUseBasicAuth default False;
    property DebugMemo: TMemo read FDebugMemo write FDebugMemo;
  end;

procedure Register;

implementation

uses
  mormot.net.client;

function GetDefaultJsonClient: IJsonClient;
begin
  Result := TJsonClient.Create('https://10.0.100.25:8443', '', 5000);
end;

constructor TPfSense.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  FHttp := TFPHTTPClient.Create(nil);
  FApiClient := TOpenapipfClient.Create(GetDefaultJsonClient);
  FBaseURL := 'https://10.0.100.25:8443';
  FBaseURLRoot := '/api/v2/';
  FUsername := '';
  FPassword := '';
  FOpenSSL := True;
  FToken := '';
  FLastResponse := '';
  FLogFileName := 'pfsense.log';
  FClientSchedules := TClientScheduleList.Create;
  FAllowedFirewallFields := TStringList.Create;
  FMaxFirewallResults := 0;
  FUseBasicAuth := False;
  FDebugMemo := nil;
end;

destructor TPfSense.Destroy;
var
  i: Integer;
begin
  for i := 0 to FClientSchedules.Count - 1 do
    FClientSchedules[i].Free;
  FClientSchedules.Free;
  FApiClient.Free;
  FHttp.Free;
  FAllowedFirewallFields.Free;
  inherited Destroy;
end;

procedure TPfSense.SetBaseURL(AValue: string);
begin
  FBaseURL := AValue;
end;

procedure TPfSense.SetBaseURLRoot(AValue: string);
begin
  FBaseURLRoot := AValue;
end;

procedure TPfSense.SetUsername(AValue: string);
begin
  FUsername := AValue;
end;

procedure TPfSense.SetPassword(AValue: string);
begin
  FPassword := AValue;
end;

procedure TPfSense.SetOpenSSL(AValue: Boolean);
begin
  FOpenSSL := AValue;
end;

procedure TPfSense.SetLogFileName(AValue: string);
begin
  FLogFileName := AValue;
end;

procedure TPfSense.SetAllowedFirewallFields(Value: TStrings);
begin
  FAllowedFirewallFields.Assign(Value);
end;

procedure TPfSense.SetMaxFirewallResults(AValue: Integer);
begin
  if AValue < 0 then
    AValue := 0;
  FMaxFirewallResults := AValue;
end;

procedure TPfSense.WriteLog(const Message: string);
var
  LogFile: TextFile;
  s: string;
begin
  s := FormatDateTime('yyyy-mm-dd hh:nn:ss', Now) + ' - ' + Message;
  AssignFile(LogFile, FLogFileName);
  try
    if FileExists(FLogFileName) then
      Append(LogFile)
    else
      Rewrite(LogFile);
    Writeln(LogFile, s);
  finally
    CloseFile(LogFile);
  end;
  if Assigned(FDebugMemo) then
  begin
    FDebugMemo.Lines.Add(s);
    FDebugMemo.SelStart := Length(FDebugMemo.Text);
    FDebugMemo.Repaint;
  end;
end;

function TPfSense.FilterFirewallJson(const JsonStr: string): string;
var
  JSONData, PropData: TJSONData;
  JSONArray, FilteredArray: TJSONArray;
  JSONObj, NewJSONObj: TJSONObject;
  i: Integer;
  Field: string;
begin
  if (FAllowedFirewallFields = nil) or (FAllowedFirewallFields.Count = 0) then
  begin
    Result := JsonStr;
    Exit;
  end;

  JSONData := GetJSON(JsonStr);
  try
    if JSONData.JSONType = jtArray then
    begin
      JSONArray := TJSONArray(JSONData);
      FilteredArray := TJSONArray.Create;
      try
        for i := 0 to JSONArray.Count - 1 do
        begin
          JSONObj := JSONArray.Objects[i];
          if Assigned(JSONObj) then
          begin
            NewJSONObj := TJSONObject.Create;
            for Field in FAllowedFirewallFields do
            begin
              PropData := JSONObj.Find(Field);
              if Assigned(PropData) then
                NewJSONObj.Add(Field, GetJSON(PropData.AsJSON));
            end;
            FilteredArray.Add(NewJSONObj);
          end
          else
            FilteredArray.Add(GetJSON(JSONArray.Items[i].AsJSON));
        end;
        Result := FilteredArray.AsJSON;
      finally
        FilteredArray.Free;
      end;
    end
    else if JSONData.JSONType = jtObject then
    begin
      JSONObj := TJSONObject(JSONData);
      NewJSONObj := TJSONObject.Create;
      try
        for Field in FAllowedFirewallFields do
        begin
          PropData := JSONObj.Find(Field);
          if Assigned(PropData) then
            NewJSONObj.Add(Field, GetJSON(PropData.AsJSON));
        end;
        Result := NewJSONObj.AsJSON;
      finally
        NewJSONObj.Free;
      end;
    end
    else
      Result := JsonStr;
  finally
    JSONData.Free;
  end;
end;

procedure TPfSense.AddAuthHeader(aHTTP: TFPHTTPClient);
var
  authValue: string;
begin
  aHTTP.RequestHeaders.Clear;
  if FUseBasicAuth or ((FToken = '') and (FUsername <> '') and (FPassword <> '')) then
    authValue := 'Basic ' + EncodeStringBase64(FUsername + ':' + FPassword)
  else if FToken <> '' then
    authValue := 'Bearer ' + FToken
  else
    Exit;
  aHTTP.AddHeader('Authorization', authValue);
  WriteLog('Auth header set: ' + authValue);
end;

function TPfSense.GetVersion: string;
var
  URL: string;
begin
  URL := FBaseURL + '/' + FBaseURLRoot + 'version';
  AddAuthHeader(FHttp);
  try
    Result := FHttp.Get(URL);
    WriteLog('GetVersion: Success, Request: ' + URL + ', Response: ' + Result);
  except
    on E: Exception do
    begin
      Result := 'Error: ' + E.Message;
      WriteLog('GetVersion Error: ' + E.Message);
    end;
  end;
  FLastResponse := Result;
end;

function TPfSense.GetFirewallRules: string;
var
  URL: string;
  FullResult: string;
begin
  URL := FBaseURL + '/' + FBaseURLRoot + 'firewall/rules';
  if FMaxFirewallResults > 0 then
    URL := URL + '?limit=' + IntToStr(FMaxFirewallResults);
  AddAuthHeader(FHttp);
  try
    FullResult := FHttp.Get(URL);
    WriteLog('GetFirewallRules: Success, Request: ' + URL + ', Response: ' + FullResult);
  except
    on E: Exception do
    begin
      FullResult := 'Error: ' + E.Message;
      WriteLog('GetFirewallRules Error: ' + E.Message);
    end;
  end;
  if (FAllowedFirewallFields <> nil) and (FAllowedFirewallFields.Count > 0) then
    Result := FilterFirewallJson(FullResult)
  else
    Result := FullResult;
  FLastResponse := Result;
end;

function TPfSense.GetFirewallRule(const RuleID: string): string;
var
  URL: string;
  FullResult: string;
begin
  URL := FBaseURL + '/' + FBaseURLRoot + 'firewall/rule?id=' + RuleID;
  AddAuthHeader(FHttp);
  try
    FullResult := FHttp.Get(URL);
    WriteLog('GetFirewallRule: Success for RuleID=' + RuleID + ', Request: ' + URL +
      ', Response: ' + FullResult);
  except
    on E: Exception do
    begin
      FullResult := 'Error: ' + E.Message;
      WriteLog('GetFirewallRule Error: ' + E.Message);
    end;
  end;
  if (FAllowedFirewallFields <> nil) and (FAllowedFirewallFields.Count > 0) then
    Result := FilterFirewallJson(FullResult)
  else
    Result := FullResult;
  FLastResponse := Result;
end;

function TPfSense.DeleteFirewallRule(const RuleID: string): string;
var
  URL: string;
begin
  URL := FBaseURL + '/' + FBaseURLRoot + 'firewall/rule?id=' + RuleID;
  AddAuthHeader(FHttp);
  try
    Result := FHttp.Delete(URL);
    WriteLog('DeleteFirewallRule: Success for RuleID=' + RuleID + ', Request: ' + URL +
      ', Response: ' + Result);
  except
    on E: Exception do
    begin
      Result := 'Error: ' + E.Message;
      WriteLog('DeleteFirewallRule Error: ' + E.Message);
    end;
  end;
  FLastResponse := Result;
end;

procedure TPfSense.ApplyChanges;
var
  URL: string;
  ResponseStr: RawByteString;
begin
  URL := FBaseURL + '/' + FBaseURLRoot + 'firewall/apply';
  AddAuthHeader(FHttp);
  ResponseStr := FHttp.Post(URL);
  FLastResponse := string(ResponseStr);
  WriteLog('ApplyChanges: Success, Request: ' + URL + ', Response: ' + FLastResponse);
end;

function TPfSense.GetLastResponse: string;
begin
  Result := FLastResponse;
end;

procedure TPfSense.AddClientSchedule(ClientName, IPAddress: string;
  AccessStartTime, AccessEndTime: TTime; RuleDescription: string);
var
  Schedule: TClientSchedule;
begin
  Schedule := TClientSchedule.Create;
  Schedule.ClientName := ClientName;
  Schedule.IPAddress := IPAddress;
  Schedule.AccessStartTime := AccessStartTime;
  Schedule.AccessEndTime := AccessEndTime;
  Schedule.RuleDescription := RuleDescription;
  FClientSchedules.Add(Schedule);
  WriteLog('AddClientSchedule: Added schedule for ' + ClientName);
end;

function TPfSense.GetClientSchedules: TClientScheduleList;
begin
  Result := FClientSchedules;
end;

function TPfSense.GetScheduleTimeRange(const ParentID, TimeRangeID: string): string;
var
  URL, response: string;
  jsonData: TJSONData;
  rootObj: TJSONObject;
  dataElement: TJSONData;
  hour, rangedescr: string;
begin
  URL := FBaseURL + '/' + FBaseURLRoot + 'firewall/schedule/time_range?parent_id=' + ParentID + '&id=' + TimeRangeID;
  AddAuthHeader(FHttp);
  try
    response := FHttp.Get(URL);
    WriteLog('GetScheduleTimeRange: Success, Request: ' + URL + ', Response: ' + response);
    jsonData := GetJSON(response);
    try
      if jsonData.JSONType = jtObject then
      begin
        rootObj := TJSONObject(jsonData);
        dataElement := rootObj.Find('data');
        if Assigned(dataElement) and (dataElement.JSONType = jtObject) then
        begin
          rootObj := TJSONObject(dataElement);
          hour := rootObj.Get('hour', '');
          rangedescr := rootObj.Get('rangedescr', '');
          Result := rangedescr + ' (' + hour + ')';
        end
        else
          Result := '';
      end
      else
        Result := '';
    finally
      jsonData.Free;
    end;
  except
    on E: Exception do
    begin
      WriteLog('GetScheduleTimeRange Error: ' + E.Message);
      Result := '';
    end;
  end;
end;

procedure Register;
begin
  RegisterComponents('Misc', [TPfSense]);
end;

end.

