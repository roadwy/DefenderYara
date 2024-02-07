
rule Trojan_BAT_AveMaria_RPV_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 69 00 64 00 61 00 6e 00 7a 00 65 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  maidanze.000webhostapp.com
		$a_01_1 = {42 00 41 00 53 00 45 00 36 00 34 00 2e 00 74 00 78 00 74 00 } //01 00  BASE64.txt
		$a_01_2 = {52 00 52 00 55 00 55 00 4e 00 4e 00 4e 00 } //01 00  RRUUNNN
		$a_01_3 = {6e 00 65 00 77 00 64 00 64 00 6c 00 6c 00 2e 00 74 00 78 00 74 00 } //01 00  newddll.txt
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}