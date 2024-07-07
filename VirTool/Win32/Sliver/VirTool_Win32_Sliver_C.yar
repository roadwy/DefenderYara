
rule VirTool_Win32_Sliver_C{
	meta:
		description = "VirTool:Win32/Sliver.C,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 73 68 6f 70 66 6f 78 2f 73 6c 69 76 65 72 2f 70 72 6f 74 6f 62 75 66 2f 73 6c 69 76 65 72 70 62 } //1 /bishopfox/sliver/protobuf/sliverpb
		$a_01_1 = {73 6c 69 76 65 72 70 62 2f 73 6c 69 76 65 72 2e 70 72 6f 74 6f } //1 sliverpb/sliver.proto
		$a_01_2 = {2e 73 6c 69 76 65 72 70 62 2e 4e 65 74 49 6e 74 65 72 66 61 63 65 } //1 .sliverpb.NetInterface
		$a_01_3 = {2e 73 6c 69 76 65 72 70 62 2e 46 69 6c 65 49 6e 66 6f } //1 .sliverpb.FileInfo
		$a_01_4 = {2e 73 6c 69 76 65 72 70 62 2e 53 6f 63 6b 54 61 62 45 6e 74 72 79 2e 53 6f 63 6b 41 64 64 72 } //1 .sliverpb.SockTabEntry.SockAddr
		$a_01_5 = {2e 73 6c 69 76 65 72 70 62 2e 44 4e 53 42 6c 6f 63 6b 48 65 61 64 65 72 } //1 .sliverpb.DNSBlockHeader
		$a_01_6 = {2e 73 6c 69 76 65 72 70 62 2e 53 65 72 76 69 63 65 49 6e 66 6f 52 65 71 } //1 .sliverpb.ServiceInfoReq
		$a_01_7 = {2e 73 6c 69 76 65 72 70 62 2e 50 69 76 6f 74 45 6e 74 72 79 } //1 .sliverpb.PivotEntry
		$a_01_8 = {2e 73 6c 69 76 65 72 70 62 2e 57 47 54 43 50 46 6f 72 77 61 72 64 65 72 } //1 .sliverpb.WGTCPForwarder
		$a_01_9 = {2e 73 6c 69 76 65 72 70 62 2e 57 47 53 6f 63 6b 73 53 65 72 76 65 72 } //1 .sliverpb.WGSocksServer
		$a_01_10 = {2e 73 6c 69 76 65 72 70 62 2e 57 69 6e 64 6f 77 73 50 72 69 76 69 6c 65 67 65 45 6e 74 72 79 } //1 .sliverpb.WindowsPrivilegeEntry
		$a_01_11 = {2e 63 6f 6d 6d 6f 6e 70 62 2e 52 65 73 70 6f 6e 73 65 } //1 .commonpb.Response
		$a_01_12 = {2e 63 6f 6d 6d 6f 6e 70 62 2e 52 65 71 75 65 73 74 } //1 .commonpb.Request
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}