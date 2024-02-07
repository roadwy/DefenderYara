
rule Trojan_BAT_AgentTesla_NVH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 02 00 06 00 28 90 01 03 06 28 90 01 02 00 06 28 90 01 02 00 06 00 28 90 01 02 00 06 d2 06 28 90 01 02 00 06 00 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}