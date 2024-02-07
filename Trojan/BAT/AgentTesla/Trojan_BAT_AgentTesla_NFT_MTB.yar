
rule Trojan_BAT_AgentTesla_NFT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 90 00 } //01 00 
		$a_81_1 = {75 47 2e 42 31 } //01 00  uG.B1
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}