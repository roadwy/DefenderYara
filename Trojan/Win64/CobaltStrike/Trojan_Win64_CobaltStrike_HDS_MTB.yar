
rule Trojan_Win64_CobaltStrike_HDS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 68 83 e8 02 0f b6 c8 8b 44 24 28 d3 f8 8b 4c 24 28 83 e1 01 8d 04 41 89 44 24 2c 8b 44 24 2c 8b 4c 24 20 8d 04 c8 89 44 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}