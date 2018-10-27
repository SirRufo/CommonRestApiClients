unit CommonRestApiClients.Commons;

interface

uses
  System.Classes, System.SysUtils,
  System.Net.HttpCLient, System.Net.Mime;

type
  EApiException           = class( Exception );
  EAuthorizationException = class( EApiException );
  ERateLimitException     = class( EApiException );
  EBadRequestException    = class( EApiException );

type
  TMultipartFormData = System.Net.Mime.TMultipartFormData;

type
  IHttpResponse = interface
    ['{B12EE780-7F20-4006-B916-2480BF4BF8A6}']
    function GetStatusCode: Integer;
    property StatusCode: Integer read GetStatusCode;

    function ContentAsString( ): string;
  end;

  IHttpClient = interface
    ['{5E3B3560-68C7-4204-9A3C-98502330397C}']
    function Get( const AUrl: string ): IHttpResponse;
    function Post( const AUrl: string; const ASource: TStrings ): IHttpResponse; overload;
    function Post( const AUrl: string; const ASource: TMultipartFormData ): IHttpResponse; overload;

    function GetBaseUrl: string;
    procedure SetBaseUrl( const Value: string );

    property BaseUrl: string read GetBaseUrl write SetBaseUrl;
  end;

  TInterfacedHttpClient = class( TInterfacedObject, IHttpClient )
  private
    FHttpClient: THttpClient;
    FBaseUrl:    string;
  protected
    function Get( const AUrl: string ): IHttpResponse;
    function Post( const AUrl: string; const ASource: TStrings ): IHttpResponse; overload;
    function Post( const AUrl: string; const ASource: TMultipartFormData ): IHttpResponse; overload;
    function GetBaseUrl: string;
    procedure SetBaseUrl( const Value: string );

  public
    constructor Create( ); overload;
    constructor Create( const ABaseUrl: string ); overload;
    destructor Destroy; override;
  end;

  THttpResponseWrapper = class( TInterfacedObject, IHttpResponse )
  private
    FWrapped: System.Net.HttpCLient.IHttpResponse;
  protected
    function ContentAsString( ): string;
    function GetStatusCode: Integer;
    property StatusCode: Integer read GetStatusCode;
  public
    constructor Create( const AWrapped: System.Net.HttpCLient.IHttpResponse );
  end;

implementation

{ TInterfacedHttpCLient }

constructor TInterfacedHttpClient.Create;
begin
  inherited;
  FHttpClient := THttpClient.Create;
end;

constructor TInterfacedHttpClient.Create( const ABaseUrl: string );
begin
  Create;
  FBaseUrl := ABaseUrl;
end;

destructor TInterfacedHttpClient.Destroy;
begin
  FHttpClient.Free;
  inherited;
end;

function TInterfacedHttpClient.Get( const AUrl: string ): IHttpResponse;
begin
  Result := THttpResponseWrapper.Create( FHttpClient.Get( FBaseUrl + AUrl ) );
end;

function TInterfacedHttpClient.GetBaseUrl: string;
begin
  Result := FBaseUrl;
end;

function TInterfacedHttpClient.Post( const AUrl: string; const ASource: TStrings ): IHttpResponse;
begin
  Result := THttpResponseWrapper.Create( FHttpClient.Post( FBaseUrl + AUrl, ASource ) );
end;

function TInterfacedHttpClient.Post( const AUrl: string; const ASource: TMultipartFormData ): IHttpResponse;
begin
  Result := THttpResponseWrapper.Create( FHttpClient.Post( FBaseUrl + AUrl, ASource ) );
end;

procedure TInterfacedHttpClient.SetBaseUrl( const Value: string );
begin
  FBaseUrl := Value;
end;

{ THttpResponseWrapper }

function THttpResponseWrapper.ContentAsString( ): string;
begin
  Result := FWrapped.ContentAsString( TEncoding.UTF8 );
end;

constructor THttpResponseWrapper.Create( const AWrapped: System.Net.HttpCLient.IHttpResponse );
begin
  inherited Create;
  if not Assigned( AWrapped )
  then
    raise EArgumentNilException.Create( 'AWrapped' );

  FWrapped := AWrapped;
end;

function THttpResponseWrapper.GetStatusCode: Integer;
begin
  Result := FWrapped.StatusCode;
end;

end.
