
rule Trojan_BAT_Stealer_MTB{
	meta:
		description = "Trojan:BAT/Stealer!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  WebResponse
		$a_81_1 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_81_2 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_81_3 = {41 70 70 44 6f 6d 61 69 6e } //01 00  AppDomain
		$a_81_4 = {57 65 62 53 65 72 76 69 63 65 73 } //01 00  WebServices
		$a_81_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_81_6 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_81_7 = {58 4f 2d 4a 41 4d 2e } //01 00  XO-JAM.
		$a_81_8 = {5f 54 50 61 73 73 77 6f 72 64 } //01 00  _TPassword
		$a_81_9 = {43 4f 2d 4a 41 4d 2e } //00 00  CO-JAM.
	condition:
		any of ($a_*)
 
}