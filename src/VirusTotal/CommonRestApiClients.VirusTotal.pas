unit CommonRestApiClients.VirusTotal;

interface

uses
  System.Classes, System.SysUtils, System.Net.HttpClient, System.NetEncoding,
  System.Generics.Collections, System.IOUtils,
  CommonRestApiClients.Commons, CommonRestApiClients.VirusTotal.Types;

type
  TVirusTotalClient = class;

  TVirusTotalEndpoint = class abstract
  private
    FClient: TVirusTotalClient;
  protected
    property Client: TVirusTotalClient read FClient;
  protected
    procedure CheckApiKey( );
    procedure CheckResponse( const AResponse: IHttpResponse );
  public
    constructor Create( const AClient: TVirusTotalClient );
  end;

  TVirusTotalFileEndpoint = class( TVirusTotalEndpoint )
  public
    function Report( const AResource: string ): TFileReportResponse;
    function Rescan( const AResource: string ): TFileRescanResponse;
    function Scan( const AFilename: TFileName ): TFileScanResponse;
  end;

  TVirusTotalUrlEndpoint = class( TVirusTotalEndpoint )
  public
    function Scan( const AUrl: string ): TUrlScanResponse;
  end;

  TVirusTotalDomainEndpoint = class( TVirusTotalEndpoint )
  public
    function Report( const ADomain: string ): TDomainReportResponse;
  end;

  TVirusTotalIpAddressEndpoint = class( TVirusTotalEndpoint )
  public
    function Report( const AIpAddress: string ): TIpAddressReportResponse;
  end;

  TVirusTotalClient = class
  public const
    BaseUrl = 'https://www.virustotal.com/vtapi/v2';
  private
    FApiKey:     string;
    FEndpoints:  TObjectDictionary<string, TVirusTotalEndpoint>;
    FHttpClient: IHttpClient;
    function GetFileEndpoint: TVirusTotalFileEndpoint;
    function GetUrlEndpoint: TVirusTotalUrlEndpoint;
    function GetDomainEndpoint: TVirusTotalDomainEndpoint;
    function GetIpAddressEndpoint: TVirusTotalIpAddressEndpoint;
  protected
    property HttpClient: IHttpClient read FHttpClient;
  public
    property ApiKey: string read FApiKey write FApiKey;

    property Domains:     TVirusTotalDomainEndpoint read GetDomainEndpoint;
    property Files:       TVirusTotalFileEndpoint read GetFileEndpoint;
    property IpAddresses: TVirusTotalIpAddressEndpoint read GetIpAddressEndpoint;
    property Urls:        TVirusTotalUrlEndpoint read GetUrlEndpoint;
  public
    constructor Create( const AHttpCLient: IHttpClient = nil );
    destructor Destroy; override;
  end;

implementation

uses
  System.Net.Mime, System.Net.URLClient, System.Json;

{ TVirusTotalEndpoint }

procedure TVirusTotalEndpoint.CheckApiKey;
begin
  if string.IsNullOrWhiteSpace( Client.ApiKey )
  then
    raise EInvalidOperation.Create( 'Client ApiKey must not be empty!' );
end;

procedure TVirusTotalEndpoint.CheckResponse( const AResponse: IHttpResponse );
begin
  if AResponse.StatusCode = 204
  then
    raise ERateLimitException.Create( 'Request rate limit exceeded. You are making more requests than allowed.' );

  if AResponse.StatusCode = 400
  then
    raise EBadRequestException.Create( 'Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.' );

  if AResponse.StatusCode = 403
  then
    raise EAuthorizationException.Create
      ( 'Forbidden. You don''t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.' );

  if AResponse.StatusCode >= 400
  then
    raise EApiException.CreateFmt( 'Statuscode: %d', [AResponse.StatusCode] );
end;

constructor TVirusTotalEndpoint.Create( const AClient: TVirusTotalClient );
begin
  inherited Create;
  if not Assigned( AClient )
  then
    raise EArgumentNilException.Create( 'AClient' );

  FClient := AClient;
end;

{ TVirusTotalFileEndpoint }

function TVirusTotalFileEndpoint.Report( const AResource: string ): TFileReportResponse;
var
  clt:     IHttpClient;
  resp:    IHttpResponse;
  jsonStr: string;
  url:     string;
begin
  if string.IsNullOrWhiteSpace( AResource )
  then
    raise EArgumentException.Create( 'AResource' );
  CheckApiKey( );

  clt  := Client.HttpClient;
  url  := string.Format( '/file/report?apikey=%s&resource=%s', [TNetEncoding.url.EncodeQuery( Client.ApiKey ), TNetEncoding.url.EncodeQuery( AResource )] );
  resp := clt.Get( url );
  CheckResponse( resp );
  jsonStr := resp.ContentAsString( );
  Result  := TFileReportResponse.FromJson( jsonStr );
end;

function TVirusTotalFileEndpoint.Rescan( const AResource: string ): TFileRescanResponse;
var
  clt:     IHttpClient;
  src:     TStrings;
  resp:    IHttpResponse;
  jsonStr: string;
begin
  if string.IsNullOrWhiteSpace( AResource )
  then
    raise EArgumentException.Create( 'AResource' );
  CheckApiKey( );

  clt := Client.HttpClient;

  src := TStringList.Create( );
  try
    src.AddPair( 'apikey', TNetEncoding.HTML.Encode( Client.ApiKey ) );
    src.AddPair( 'resource', TNetEncoding.HTML.Encode( AResource ) );

    resp := clt.Post( '/file/rescan', src );
    CheckResponse( resp );
  finally
    src.Free;
  end;

  jsonStr := resp.ContentAsString( );
  Result  := TFileRescanResponse.FromJson( jsonStr );
end;

function TVirusTotalFileEndpoint.Scan( const AFilename: TFileName ): TFileScanResponse;
var
  clt:     IHttpClient;
  src:     TMultipartFormData;
  resp:    IHttpResponse;
  jsonStr: string;
begin
  if not TFile.Exists(AFilename)
  then
    raise EArgumentException.Create( 'AFilename' );
  CheckApiKey( );

  clt := Client.HttpClient;

  src := TMultipartFormData.Create( );
  try
    src.AddField( 'apikey', Client.ApiKey );
    src.AddFile( 'file', AFilename );

    resp := clt.Post( '/file/scan', src );
    CheckResponse( resp );
  finally
    src.Free;
  end;

  jsonStr := resp.ContentAsString( );

  Result := TFileScanResponse.FromJson( jsonStr );
end;

{ TVirusTotalClient }

constructor TVirusTotalClient.Create( const AHttpCLient: IHttpClient = nil );
begin
  inherited Create;
  FEndpoints := TObjectDictionary<string, TVirusTotalEndpoint>.Create( [doOwnsValues] );
  if AHttpCLient = nil
  then
    FHttpClient := TInterfacedHttpClient.Create( BaseUrl )
  else
    begin
      FHttpClient         := AHttpCLient;
      FHttpClient.BaseUrl := BaseUrl;
    end;
end;

destructor TVirusTotalClient.Destroy;
begin
  FEndpoints.Free;
  inherited;
end;

function TVirusTotalClient.GetDomainEndpoint: TVirusTotalDomainEndpoint;
const
  name = 'domain';
begin
  if not FEndpoints.ContainsKey( name )
  then
    FEndpoints.Add( name, TVirusTotalDomainEndpoint.Create( Self ) );

  Result := FEndpoints[name] as TVirusTotalDomainEndpoint;
end;

function TVirusTotalClient.GetFileEndpoint: TVirusTotalFileEndpoint;
const
  name = 'file';
begin
  if not FEndpoints.ContainsKey( name )
  then
    FEndpoints.Add( name, TVirusTotalFileEndpoint.Create( Self ) );

  Result := FEndpoints[name] as TVirusTotalFileEndpoint;
end;

function TVirusTotalClient.GetIpAddressEndpoint: TVirusTotalIpAddressEndpoint;
const
  name = 'ip-address';
begin
  if not FEndpoints.ContainsKey( name )
  then
    FEndpoints.Add( name, TVirusTotalIpAddressEndpoint.Create( Self ) );

  Result := FEndpoints[name] as TVirusTotalIpAddressEndpoint;
end;

function TVirusTotalClient.GetUrlEndpoint: TVirusTotalUrlEndpoint;
const
  name = 'url';
begin
  if not FEndpoints.ContainsKey( name )
  then
    FEndpoints.Add( name, TVirusTotalUrlEndpoint.Create( Self ) );

  Result := FEndpoints[name] as TVirusTotalUrlEndpoint;
end;

{ TVirusTotalUrlEndpoint }

function TVirusTotalUrlEndpoint.Scan( const AUrl: string ): TUrlScanResponse;
var
  clt:     IHttpClient;
  url:     string;
  src:     TMultipartFormData;
  resp:    IHttpResponse;
  jsonStr: string;
begin
  if string.IsNullOrWhiteSpace( AUrl )
  then
    raise EArgumentException.Create( 'AUrl' );
  CheckApiKey( );

  clt := Client.HttpClient;
  url := '/url/scan';
  src := TMultipartFormData.Create( );
  try
    src.AddField( 'apikey', Client.ApiKey );
    src.AddField( 'url', AUrl );

    resp := clt.Post( url, src );
  finally
    src.Free;
  end;

  CheckResponse( resp );

  jsonStr := resp.ContentAsString( );
  Result  := TUrlScanResponse.FromJson( jsonStr );
end;

{ TVirusTotalDomainEndpoint }

function TVirusTotalDomainEndpoint.Report( const ADomain: string ): TDomainReportResponse;
var
  clt:     IHttpClient;
  url:     string;
  resp:    IHttpResponse;
  jsonStr: string;
begin
  if string.IsNullOrWhiteSpace( ADomain )
  then
    raise EArgumentException.Create( 'ADomain' );
  CheckApiKey( );

  clt := Client.HttpClient;
  url := string.Format( '/domain/report?apikey=%s&domain=%s', [TNetEncoding.url.EncodeQuery( Client.ApiKey ), TNetEncoding.url.EncodeQuery( ADomain )] );

  resp := clt.Get( url );

  CheckResponse( resp );

  jsonStr := resp.ContentAsString( );
  Result  := TDomainReportResponse.FromJson( jsonStr );
end;

{ TVirusTotalIpAddressEndpoint }

function TVirusTotalIpAddressEndpoint.Report( const AIpAddress: string ): TIpAddressReportResponse;
var
  clt:     IHttpClient;
  url:     string;
  resp:    IHttpResponse;
  jsonStr: string;
begin
  if string.IsNullOrWhiteSpace( AIpAddress )
  then
    raise EArgumentException.Create( 'AIpAddress' );
  CheckApiKey( );

  clt := Client.HttpClient;
  url := string.Format( '/ip-address/report?apikey=%s&ip=%s', [TNetEncoding.url.EncodeQuery( Client.ApiKey ), TNetEncoding.url.EncodeQuery( AIpAddress )] );

  resp := clt.Get( url );

  CheckResponse( resp );

  jsonStr := resp.ContentAsString( );
  Result  := TIpAddressReportResponse.FromJson( jsonStr );
end;

end.
