
rule Trojan_BAT_AgentTesla_APJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {17 da 13 06 16 0b 2b 1e 09 06 07 90 01 05 13 07 11 07 90 01 05 13 08 11 04 08 11 08 b4 9c 07 17 d6 0b 07 11 06 31 90 01 01 08 17 d6 0c 06 17 d6 0a 06 11 05 31 90 00 } //01 00 
		$a_81_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_2 = {54 6f 57 69 6e 33 32 } //00 00  ToWin32
	condition:
		any of ($a_*)
 
}