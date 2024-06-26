
rule TrojanProxy_Win32_Banker_AN{
	meta:
		description = "TrojanProxy:Win32/Banker.AN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 65 73 63 6f 22 2c 20 22 62 62 22 2c 20 22 68 22 2c 20 22 73 62 63 22 } //01 00  "esco", "bb", "h", "sbc"
		$a_01_1 = {22 65 64 69 22 2c 20 22 63 61 22 2c 20 22 72 64 22 2c 20 22 69 6e 66 22 } //01 00  "edi", "ca", "rd", "inf"
		$a_01_2 = {75 72 6c 73 54 6f 50 72 6f 78 79 } //01 00  urlsToProxy
		$a_01_3 = {46 69 6e 64 50 72 6f 78 79 46 6f 72 55 52 4c 28 75 72 6c 2c 20 68 6f 73 74 29 } //01 00  FindProxyForURL(url, host)
		$a_01_4 = {57 69 6e 4e 54 53 65 72 76 69 63 65 2e 76 62 73 } //00 00  WinNTService.vbs
		$a_00_5 = {80 10 00 } //00 88 
	condition:
		any of ($a_*)
 
}