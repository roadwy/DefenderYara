
rule TrojanSpy_Win32_Banker_PQ{
	meta:
		description = "TrojanSpy:Win32/Banker.PQ,SIGNATURE_TYPE_PEHSTR_EXT,62 00 62 00 11 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 6f 6f 74 43 65 72 74 46 69 6c 65 } //0a 00  RootCertFile
		$a_01_1 = {53 53 4c 49 4f 48 61 6e 64 6c 65 72 53 6f 63 6b 65 74 } //0a 00  SSLIOHandlerSocket
		$a_01_2 = {49 64 43 6f 6f 6b 69 65 4c 69 73 74 } //0a 00  IdCookieList
		$a_01_3 = {49 64 48 54 54 50 4d 65 74 68 6f 64 } //0a 00  IdHTTPMethod
		$a_01_4 = {53 51 4c 43 6f 6e 6e 65 63 74 69 6f 6e } //0a 00  SQLConnection
		$a_01_5 = {4a 50 45 47 49 6d 61 67 65 } //0a 00  JPEGImage
		$a_01_6 = {47 49 46 49 6d 61 67 65 } //0a 00  GIFImage
		$a_01_7 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //01 00  Internet Explorer_Server
		$a_00_8 = {61 67 72 69 63 6f 6c 61 } //01 00  agricola
		$a_00_9 = {62 70 69 65 6d 70 72 65 73 61 } //01 00  bpiempresa
		$a_00_10 = {6d 6f 6e 74 65 70 69 6f } //01 00  montepio
		$a_00_11 = {63 69 74 69 } //01 00  citi
		$a_00_12 = {63 67 64 65 6d 70 72 65 73 61 } //01 00  cgdempresa
		$a_00_13 = {62 61 6e 66 69 } //05 00  banfi
		$a_00_14 = {69 6e 76 e1 6c 69 64 6f } //05 00 
		$a_00_15 = {63 76 76 32 } //05 00  cvv2
		$a_00_16 = {63 6f 6e 66 69 72 6d 65 } //00 00  confirme
	condition:
		any of ($a_*)
 
}