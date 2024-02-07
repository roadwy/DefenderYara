
rule Trojan_BAT_AgentTesla_BPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 09 18 d6 16 2d 90 00 } //01 00 
		$a_02_1 = {91 08 61 07 11 07 91 61 b4 9c 11 07 03 6f 90 01 03 0a 17 da 16 2d 90 00 } //01 00 
		$a_81_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_3 = {54 6f 49 6e 74 33 32 } //00 00  ToInt32
	condition:
		any of ($a_*)
 
}