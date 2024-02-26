
rule Trojan_Win64_Darkgen_RPY_MTB{
	meta:
		description = "Trojan:Win64/Darkgen.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 53 71 33 c9 44 8d 4b 04 41 b8 00 30 00 00 ff 55 80 48 89 85 c8 00 00 00 48 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}