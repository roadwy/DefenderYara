
rule Trojan_BAT_RedLineStealer_VV_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 63 20 74 69 6d 65 6f 75 74 20 2f 6e 6f 62 72 65 61 6b 20 2f 74 } ///c timeout /nobreak /t  01 00 
		$a_80_1 = {33 37 2e 30 2e 31 31 2e 31 36 34 } //37.0.11.164  01 00 
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_80_6 = {52 65 6e 65 76 63 74 } //Renevct  00 00 
	condition:
		any of ($a_*)
 
}