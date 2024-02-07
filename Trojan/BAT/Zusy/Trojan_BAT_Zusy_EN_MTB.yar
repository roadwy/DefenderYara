
rule Trojan_BAT_Zusy_EN_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 16 00 00 00 15 00 00 00 18 00 00 00 02 00 00 00 3b 00 00 00 0e 00 00 00 05 00 00 00 02 00 00 00 01 00 00 00 04 } //01 00 
		$a_01_1 = {50 72 6f 6a 65 63 74 2e 52 75 6d 6d 61 67 65 2e 65 78 65 } //01 00  Project.Rummage.exe
		$a_01_2 = {47 65 74 53 75 62 4b 65 79 4e 61 6d 65 73 } //01 00  GetSubKeyNames
		$a_01_3 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_5 = {50 72 6f 78 79 55 73 65 } //00 00  ProxyUse
	condition:
		any of ($a_*)
 
}