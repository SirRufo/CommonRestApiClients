unit CommonRestApiClients.VirusTotal.Types;

interface

uses
  XSuperObject, XSuperJSON;

type
  TCommonResponse = packed record
  public
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
  public
    class function FromJson( const AJson: string ): TCommonResponse; static;
  end;

  TFileReportResponse = packed record
  public type
    TScanData = packed record
    public
      [ALIAS( 'detected' )]
      Detected: Boolean;
      [ALIAS( 'version' )]
      Version: string;
      [ALIAS( 'result' )]
      Result: string;
      [ALIAS( 'update' )]
      Update: string;
    end;

    TScanItem = packed record
    public
      Name: string;
      Data: TScanData;
    end;
  public
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'resource' )]
    Resource: string;
    [ALIAS( 'scan_id' )]
    ScanId: string;
    [ALIAS( 'md5' )]
    MD5: string;
    [ALIAS( 'sha1' )]
    SHA1: string;
    [ALIAS( 'sha256' )]
    SHA256: string;
    [ALIAS( 'scan_date' )]
    ScanDate: string;
    [ALIAS( 'permalink' )]
    Permalink: string;
    [ALIAS( 'positives' )]
    Positives: Integer;
    [ALIAS( 'totals' )]
    Totals: Integer;
    [DISABLE]
    Scans: TArray<TScanItem>;
  public
    class function FromJson( const AJson: string ): TFileReportResponse; static;
  end;

  TFileRescanResponse = packed record
  public
    [ALIAS( 'permalink' )]
    Permalink: string;
    [ALIAS( 'resource' )]
    Resource: string;
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'scan_id' )]
    ScanId: string;
    [ALIAS( 'sha256' )]
    SHA256: string;
  public
    class function FromJson( const AJson: string ): TFileRescanResponse; static;
  end;

  TFileScanResponse = packed record
  public
    [ALIAS( 'permalink' )]
    Permalink: string;
    [ALIAS( 'resource' )]
    Resource: string;
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'scan_id' )]
    ScanId: string;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'sha256' )]
    SHA256: string;
  public
    class function FromJson( const AJson: string ): TFileScanResponse; static;
  end;

  TUrlReportResponse = packed record
  public type
    TScanData = packed record
    public
      [ALIAS( 'detected' )]
      Detected: Boolean;
      [ALIAS( 'result' )]
      Result: string;
    end;

    TScanItem = packed record
      Name: string;
      Data: TScanData;
    end;
  public
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'scan_id' )]
    ScanId: string;
    [ALIAS( 'permalink' )]
    Permalink: string;
    [ALIAS( 'url' )]
    Url: string;
    [ALIAS( 'scan_date' )]
    ScanDate: string;
    [ALIAS( 'filescan_id' )]
    FilescanId: string;
    [ALIAS( 'positives' )]
    Positives: Integer;
    [ALIAS( 'totals' )]
    Totals: Integer;
    [DISABLE]
    Scans: TArray<TScanItem>;
  public
    class function FromJson( const AJson: string ): TUrlReportResponse; static;
  end;

  TUrlScanResponse = packed record
  public
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'resource' )]
    Resource: string;
    [ALIAS( 'scan_id' )]
    ScanId: string;
    [ALIAS( 'scan_date' )]
    ScanDate: string;
    [ALIAS( 'url' )]
    Url: string;
    [ALIAS( 'permalink' )]
    Permalink: string;
  public
    class function FromJson( const AJson: string ): TUrlScanResponse; static;
  end;

  TDomainReportResponse = packed record
  public type
    TSampleData = packed record
    public
      [ALIAS( 'date' )]
      Date: string;
      [ALIAS( 'positives' )]
      Positives: Integer;
      [ALIAS( 'total' )]
      Total: Integer;
      [ALIAS( 'sha256' )]
      SHA256: string;
    end;

    TResolutionData = packed record
    public
      [ALIAS( 'last_resolved' )]
      LastResolved: string;
      [ALIAS( 'ip_address' )]
      IpAddress: string;
    end;

    TUrlData = packed record
    public
      [ALIAS( 'url' )]
      Url: string;
      [ALIAS( 'positives' )]
      Positives: Integer;
      [ALIAS( 'total' )]
      Total: Integer;
      [ALIAS( 'scan_date' )]
      ScanDate: string;
    end;

    TUndetectedUrlData = packed record
    public
      [ALIAS( 'url' )]
      Url: string;
      [ALIAS( 'sha256' )]
      SHA256: string;
      [ALIAS( 'positives' )]
      Positives: Integer;
      [ALIAS( 'total' )]
      Total: Integer;
      [ALIAS( 'scan_date' )]
      ScanDate: string;
    end;

    TWebutationDomainInfo = packed record
    public
      [ALIAS( 'Safety score' )]
      SafetyScore: Integer;
      [ALIAS( 'Adult content' )]
      AdultContent: string;
      [ALIAS( 'Verdict' )]
      Verdict: string;
    end;

    TWotDomainInfo = packed record
    public
      [ALIAS( 'Vendor reliability' )]
      VendorReliability: string;
      [ALIAS( 'Child safety' )]
      ChildSafety: string;
      [ALIAS( 'Trustworthiness' )]
      Trustworthiness: string;
      [ALIAS( 'Privacy' )]
      Privacy: string;
    end;

  public
    [ALIAS( 'undetected_referrer_samples' )]
    UndetectedReferrerSamples: TArray<TSampleData>;
    [ALIAS( 'whois_timestamp' )]
    WhoisTimestamp: Integer;
    [ALIAS( 'whois' )]
    Whois: string;
    [ALIAS( 'detected_downloaded_samples' )]
    DetectedDownloadedSamples: TArray<TSampleData>;
    [ALIAS( 'detected_referrer_samples' )]
    DetectedReferrerSamples: TArray<TSampleData>;
    [ALIAS( 'undetected_downloaded_samples' )]
    UndetectedDownloadedSamples: TArray<TSampleData>;
    [ALIAS( 'resolutions' )]
    Resolutions: TArray<TResolutionData>;
    [ALIAS( 'subdomains' )]
    Subdomains: TArray<string>;
    [ALIAS( 'categories' )]
    Categories: TArray<string>;
    [ALIAS( 'domain_siblings' )]
    DomainSiblings: TArray<string>;
    [DISABLE]
    UndetectedUrls: TArray<TUndetectedUrlData>;
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'detected_urls' )]
    DetectedUrls: TArray<TUrlData>;
    [ALIAS( 'Webutation domain info' )]
    WebutationDomainInfo: TWebutationDomainInfo;
    [ALIAS( 'WOT domain info' )]
    WotDomainInfo: TWotDomainInfo;
    [ALIAS( 'Alexa category' )]
    AlexaCategory: string;
    [ALIAS( 'Opera domain info' )]
    OperaDomainInfo: string;
    [ALIAS( 'TrendMicro category' )]
    TrendMicroCategory: string;
    [ALIAS( 'BitDefender domain info' )]
    BitDefenderDomainInfo: string;
    [ALIAS( 'Alexa domain info' )]
    AlexaDomainInfo: string;
    [ALIAS( 'Forcepoint ThreatSeeker category' )]
    ForcepointThreatSeekerCategory: string;
    [ALIAS( 'Websense ThreatSeeker category' )]
    WebsenseThreatSeekerCategory: string;
    [ALIAS( 'pcaps' )]
    Pcaps: TArray<string>;
  public
    class function FromJson( const AJson: string ): TDomainReportResponse; static;
  end;

  TIpAddressReportResponse = packed record
  public type

    TUndetectedUrlData = packed record
    public
      [ALIAS( 'url' )]
      Url: string;
      [ALIAS( 'sha256' )]
      SHA256: string;
      [ALIAS( 'positives' )]
      Positives: Integer;
      [ALIAS( 'total' )]
      Total: Integer;
      [ALIAS( 'scan_date' )]
      ScanDate: string;
    end;

    TSampleData = packed record
    public
      [ALIAS( 'date' )]
      Date: string;
      [ALIAS( 'positives' )]
      Positives: Integer;
      [ALIAS( 'total' )]
      Total: Integer;
      [ALIAS( 'sha256' )]
      SHA256: string;
    end;

    TUrlData = packed record
    public
      [ALIAS( 'url' )]
      Url: string;
      [ALIAS( 'positives' )]
      Positives: Integer;
      [ALIAS( 'total' )]
      Total: Integer;
      [ALIAS( 'scan_date' )]
      ScanDate: string;
    end;

    TResolutionData = packed record
    public
      [ALIAS( 'last_resolved' )]
      LastResolved: string;
      [ALIAS( 'hostname' )]
      Hostname: string;
    end;

  public
    [DISABLE]
    UndetectedUrls: TArray<TUndetectedUrlData>;
    [ALIAS( 'undetected_downloaded_samples' )]
    UndetectedDownloadSamples: TArray<TSampleData>;
    [ALIAS( 'detected_download_samples' )]
    DetectedDownloadSamples: TArray<TSampleData>;
    [ALIAS( 'response_code' )]
    ResponseCode: Integer;
    [ALIAS( 'as_owner' )]
    AsOwner: string;
    [ALIAS( 'detected_urls' )]
    DetectedUrls: TArray<TUrlData>;
    [ALIAS( 'verbose_msg' )]
    VerboseMsg: string;
    [ALIAS( 'country' )]
    Country: string;
    [ALIAS( 'resolutions' )]
    Resolutions: TArray<TResolutionData>;
    [ALIAS( 'asn' )]
    ASN: Integer;
  public
    class function FromJson( const AJson: string ): TIpAddressReportResponse; static;
  end;

implementation

{ TCommonResponse }

class function TCommonResponse.FromJson( const AJson: string ): TCommonResponse;
begin
  Result := TSuperRecord<TCommonResponse>.FromJson( AJson );
end;

{ TFileReportResponse }

class function TFileReportResponse.FromJson( const AJson: string ): TFileReportResponse;
var
  obj, Scans: ISuperObject;
  scan:       ICast;
  scanItem:   TScanItem;
  idx:        Integer;
begin
  obj    := SO( AJson );
  Result := XSuperObject.TSuperRecord<TFileReportResponse>.FromJson( obj );
  if obj.Contains( 'scans' )
  then
    begin
      Scans := obj.O['scans'];
      SetLength( Result.Scans, Scans.Count );
      idx := 0;
      for scan in Scans do
        begin

          scanItem.Name := scan.Name;
          scanItem.Data := TSuperRecord<TScanData>.FromJson( scan.AsObject );

          Result.Scans[idx] := scanItem;
          Inc( idx );
        end;
    end;
end;

{ TFileRescanResponse }

class function TFileRescanResponse.FromJson( const AJson: string ): TFileRescanResponse;
begin
  Result := TSuperRecord<TFileRescanResponse>.FromJson( AJson );
end;

{ TFileScanResponse }

class function TFileScanResponse.FromJson( const AJson: string ): TFileScanResponse;
begin
  Result := TSuperRecord<TFileScanResponse>.FromJson( AJson );
end;

{ TUrlScanResponse }

class function TUrlScanResponse.FromJson( const AJson: string ): TUrlScanResponse;
begin
  Result := TSuperRecord<TUrlScanResponse>.FromJson( AJson );
end;

{ TUrlReportResponse }

class function TUrlReportResponse.FromJson( const AJson: string ): TUrlReportResponse;
var
  obj, Scans: ISuperObject;
  scan:       ICast;
  scanItem:   TScanItem;
  idx:        Integer;
begin
  obj         := SO( AJson );
  Result := XSuperObject.TSuperRecord<TUrlReportResponse>.FromJson( obj );
  if obj.Contains( 'scans' )
  then
    begin
      Scans := obj.O['scans'];
      SetLength( Result.Scans, Scans.Count );
      idx := 0;
      for scan in Scans do
        begin

          scanItem.Name := scan.Name;
          scanItem.Data := TSuperRecord<TScanData>.FromJson( scan.AsObject );

          Result.Scans[idx] := scanItem;
          Inc( idx );
        end;
    end;
end;

{ TDomainReportResponse }

class function TDomainReportResponse.FromJson( const AJson: string ): TDomainReportResponse;
var
  obj: ISuperObject;
  a:   ISuperArray;
  idx: Integer;
begin
  obj := SO( AJson );

  Result := TSuperRecord<TDomainReportResponse>.FromJson( obj );

  a := obj.a['undetected_urls'];
  SetLength( Result.UndetectedUrls, a.Length );

  for idx := 0 to a.Length - 1 do
    begin
      Result.UndetectedUrls[idx].Url       := a.a[idx].S[0];
      Result.UndetectedUrls[idx].SHA256    := a.a[idx].S[1];
      Result.UndetectedUrls[idx].Positives := a.a[idx].I[2];
      Result.UndetectedUrls[idx].Total     := a.a[idx].I[3];
      Result.UndetectedUrls[idx].ScanDate  := a.a[idx].S[4];
    end;

end;

{ TIpAddressReportResponse }

class function TIpAddressReportResponse.FromJson( const AJson: string ): TIpAddressReportResponse;
var
  obj: ISuperObject;
  a:   ISuperArray;
  idx: Integer;
begin
  obj    := SO( AJson );
  Result := TSuperRecord<TIpAddressReportResponse>.FromJson( obj );

  a := obj.a['undetected_urls'];
  SetLength( Result.UndetectedUrls, a.Length );

  for idx := 0 to a.Length - 1 do
    begin
      Result.UndetectedUrls[idx].Url       := a.a[idx].S[0];
      Result.UndetectedUrls[idx].SHA256    := a.a[idx].S[1];
      Result.UndetectedUrls[idx].Positives := a.a[idx].I[2];
      Result.UndetectedUrls[idx].Total     := a.a[idx].I[3];
      Result.UndetectedUrls[idx].ScanDate  := a.a[idx].S[4];
    end;
end;

end.
