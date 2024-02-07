
rule Trojan_BAT_AgentTesla_MUR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {20 00 01 00 00 14 14 19 8d 90 01 04 25 16 28 90 01 04 a2 25 17 28 90 01 04 a2 25 18 72 90 01 04 a2 6f 90 01 04 26 90 00 } //02 00 
		$a_80_1 = {4d 69 6e 6f 72 56 65 72 73 69 6f 6e } //MinorVersion  02 00 
		$a_80_2 = {42 69 74 6d 61 70 } //Bitmap  02 00 
		$a_00_3 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //02 00  GetResourceString
		$a_80_4 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //GetObjectValue  00 00 
	condition:
		any of ($a_*)
 
}