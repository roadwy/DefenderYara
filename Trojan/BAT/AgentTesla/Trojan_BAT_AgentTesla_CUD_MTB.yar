
rule Trojan_BAT_AgentTesla_CUD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 90 00 } //01 00 
		$a_00_1 = {09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_01_5 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_6 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}