unit TVirusTotalClientTests;

interface

uses
  System.Classes, System.SysUtils,
  DUnitX.TestFramework, CommonRestApiClients.TestUtils,
  CommonRestApiClients.Commons, CommonRestApiClients.VirusTotal,
  CommonRestApiClients.VirusTotal.Types;

type

  [TestFixture]
  TMyTestObject = class( TObject )
  const
    ApiKey   = '0011223344556677889900';
    Resource = '00112233445566778899000011223344556677889900';
  private
    FHttpClient: TTestHttpClient;
    FClient:     TVirusTotalClient;
  protected
    property HttpClient: TTestHttpClient read FHttpClient;
    property Client:     TVirusTotalClient read FClient;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure File_Scan;

    [Test]
    procedure Domain_Report_WhenDomainIsEmpty_ThenArgumentExceptionRaised;
    [Test]
    procedure Domain_Report_WhenDomainIsWhitespace_ThenArgumentExceptionRaised;
    [Test]
    procedure Domain_Report_WhenApiKeyIsEmpty_ThenInvalidOperationExceptionRaised;
    [Test]
    procedure Domain_Report_WhenRateLimitResponse_ThenRateLimitExceptionRaised;
    [Test]
    procedure Domain_Report_WhenResponseStatusCode400_ThenBadRequestExceptionRaised;
    [Test]
    procedure Domain_Report_WhenResponseStatusCode403_ThenAuthorizationExceptionRaised;
    [Test]
    [TestCase( 'Unauthorized', '401' )]
    [TestCase( 'Payment Required', '402' )]
    [TestCase( 'Not found', '404' )]
    [TestCase( 'Method not allowed', '405' )]
    [TestCase( 'Not acceptable', '406' )]
    procedure Domain_Report_OnResponseStatusCode_ApiExceptionIsRaised( StatusCode: Integer );

    (*
      // Test with TestCase Attribute to supply parameters.
      [Test]
      [TestCase( 'TestA', '1,2' )]
      [TestCase( 'TestB', '3,4' )]
      procedure Test2( const AValue1: Integer; const AValue2: Integer );
    *)
  end;

implementation

procedure TMyTestObject.Setup;
begin
  FHttpClient    := TTestHttpClient.Create;
  FClient        := TVirusTotalClient.Create( FHttpClient );
  FClient.ApiKey := ApiKey;
end;

procedure TMyTestObject.TearDown;
begin
  FClient.Free;
  FHttpClient.Free;
end;

procedure TMyTestObject.Domain_Report_OnResponseStatusCode_ApiExceptionIsRaised( StatusCode: Integer );
begin
  HttpClient.OnGet := function( Url: string ): IHttpResponse
    begin
      Result := THttpStringResponse.Create( StatusCode, string.Empty );
    end;

  Assert.WillRaise(
      procedure
    begin
      Client.Domains.Report( 'domain.de' );
    end, EApiException );
end;

procedure TMyTestObject.Domain_Report_WhenApiKeyIsEmpty_ThenInvalidOperationExceptionRaised;
begin
  Client.ApiKey := string.Empty;
  Assert.WillRaise(
    procedure
    begin
      Client.Domains.Report( 'test.de' );
    end, EInvalidOperation );
end;

procedure TMyTestObject.Domain_Report_WhenDomainIsEmpty_ThenArgumentExceptionRaised;
begin
  Assert.WillRaise(
    procedure
    begin
      Client.Domains.Report( string.Empty );
    end, EArgumentException );
end;

procedure TMyTestObject.Domain_Report_WhenDomainIsWhitespace_ThenArgumentExceptionRaised;
begin
  Assert.WillRaise(
    procedure
    begin
      Client.Domains.Report( ' ' );
    end, EArgumentException );
end;

procedure TMyTestObject.Domain_Report_WhenRateLimitResponse_ThenRateLimitExceptionRaised;
begin
  HttpClient.OnGet := function( Url: string ): IHttpResponse
    begin
      Result := THttpStringResponse.Create( 204, string.Empty );
    end;

  Assert.WillRaise(
    procedure
    begin
      Client.Domains.Report( 'domain.de' );
    end, ERateLimitException );
end;

procedure TMyTestObject.Domain_Report_WhenResponseStatusCode400_ThenBadRequestExceptionRaised;
begin
  HttpClient.OnGet := function( Url: string ): IHttpResponse
    begin
      Result := THttpStringResponse.Create( 400, string.Empty );
    end;

  Assert.WillRaise(
    procedure
    begin
      Client.Domains.Report( 'domain.de' );
    end, EBadRequestException );
end;

procedure TMyTestObject.Domain_Report_WhenResponseStatusCode403_ThenAuthorizationExceptionRaised;
begin
  HttpClient.OnGet := function( Url: string ): IHttpResponse
    begin
      Result := THttpStringResponse.Create( 403, string.Empty );
    end;

  Assert.WillRaise(
    procedure
    begin
      Client.Domains.Report( 'domain.de' );
    end, EAuthorizationException );
end;

procedure TMyTestObject.File_Scan;
var
  resp: TFileScanResponse;
begin
  HttpClient.OnPostForm := function( Url: string; Form: TMultipartFormData ): IHttpResponse
    var
      ss: TStringStream;
      s:  string;
    begin
      Assert.AreEqual( '/file/scan', Url );

      ss := TStringStream.Create;
      try
        Form.Stream.SaveToStream( ss );
        s := ss.DataString;
      finally
        ss.Free;
      end;

      Assert.IsTrue( s.Contains( 'name="apikey"'#$0D#$0A#$0D#$0A + ApiKey ), 'ApiKey is missing' );

      Result := THttpStringResponse.Create( 200,
      //
        '{' + sLineBreak + //
        '  "permalink": "https://www.virustotal.com/file/d140c...244ef892e5/analysis/1359112395/",' + sLineBreak + //
        '  "resource": "d140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556",' + sLineBreak + //
        '  "response_code": 1,' + sLineBreak + //
        '  "scan_id": "d140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556-1359112395",' + sLineBreak + //
        '  "verbose_msg": "Scan request successfully queued, come back later for the report",' + sLineBreak + //
        '  "sha256": "d140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556"' + sLineBreak + //
        '}' );
    end;

  resp := Client.Files.Scan( ParamStr( 0 ) );

  Assert.AreEqual( 'https://www.virustotal.com/file/d140c...244ef892e5/analysis/1359112395/', resp.Permalink, 'Permalink' );
  Assert.AreEqual( 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556', resp.Resource, 'Resource' );
  Assert.AreEqual( 1, resp.ResponseCode, 'ResponseCode' );
  Assert.AreEqual( 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556-1359112395', resp.ScanId, 'ScanId' );
  Assert.AreEqual( 'Scan request successfully queued, come back later for the report', resp.VerboseMsg, 'VerboseMsg' );
  Assert.AreEqual( 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556', resp.SHA256, 'SHA256' );
end;

initialization

TDUnitX.RegisterTestFixture( TMyTestObject );

end.
