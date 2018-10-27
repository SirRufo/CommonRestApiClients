unit CommonRestApiClients.TestUtils;

interface

uses
  System.Classes, System.SysUtils,
  CommonRestApiClients.Commons;

type
  IHttpClient   = CommonRestApiClients.Commons.IHttpClient;
  IHttpResponse = CommonRestApiClients.Commons.IHttpResponse;

type
  TTestHttpClient = class( TInterfacedPersistent, IHttpClient )
  private
    FBaseUrl:       string;
    FOnGet:         TFunc<string, IHttpResponse>;
    FOnPostStrings: TFunc<string, TStrings, IHttpResponse>;
    FOnPostForm:    TFunc<string, TMultipartFormData, IHttpResponse>;
  protected
    function Get( const AUrl: string ): IHttpResponse;
    function Post( const AUrl: string; const ASource: TStrings ): IHttpResponse; overload;
    function Post( const AUrl: string; const ASource: TMultipartFormData ): IHttpResponse; overload;

    function GetBaseUrl: string;
    procedure SetBaseUrl( const Value: string );

    property BaseUrl: string read GetBaseUrl write SetBaseUrl;
  public
    property OnGet:         TFunc<string, IHttpResponse> read FOnGet write FOnGet;
    property OnPostStrings: TFunc<string, TStrings, IHttpResponse> read FOnPostStrings write FOnPostStrings;
    property OnPostForm:    TFunc<string, TMultipartFormData, IHttpResponse> read FOnPostForm write FOnPostForm;
  end;

  THttpStringResponse = class( TInterfacedObject, IHttpResponse )
  private
    FContent:    string;
    FStatusCode: Integer;
  protected
    function GetStatusCode: Integer;
    property StatusCode: Integer read GetStatusCode;

    function ContentAsString( ): string;
  public
    constructor Create( AStatusCode: Integer; const AContent: String );
  end;

implementation

{ TTestHttpClient }

function TTestHttpClient.Get( const AUrl: string ): IHttpResponse;
begin
  Result := OnGet( AUrl );
end;

function TTestHttpClient.GetBaseUrl: string;
begin
  Result := FBaseUrl;
end;

function TTestHttpClient.Post( const AUrl: string; const ASource: TStrings ): IHttpResponse;
begin
  Result := OnPostStrings( AUrl, ASource );
end;

function TTestHttpClient.Post( const AUrl: string; const ASource: TMultipartFormData ): IHttpResponse;
begin
  Result := OnPostForm( AUrl, ASource );
end;

procedure TTestHttpClient.SetBaseUrl( const Value: string );
begin
  FBaseUrl := Value;
end;

{ THttpStringResponse }

function THttpStringResponse.ContentAsString: string;
begin
  Result := FContent;
end;

constructor THttpStringResponse.Create( AStatusCode: Integer;
  const AContent: String );
begin
  inherited Create;
  FStatusCode := AStatusCode;
  FContent    := AContent;
end;

function THttpStringResponse.GetStatusCode: Integer;
begin
  Result := FStatusCode;
end;

end.
