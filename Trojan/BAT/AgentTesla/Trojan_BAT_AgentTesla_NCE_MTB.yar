
rule Trojan_BAT_AgentTesla_NCE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 2a 00 08 09 11 04 6f ?? ?? ?? 0a 13 07 11 07 28 ?? ?? ?? 0a 13 08 17 13 09 07 09 11 08 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d cb } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}