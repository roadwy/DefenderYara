
rule Trojan_Win64_BlackWidow_RPY_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 8b 40 20 48 8b 4c 24 70 48 03 c8 48 8b c1 8b 4c 24 20 48 8d 04 88 48 89 44 24 38 48 8b 44 24 38 8b 00 48 8b 4c 24 70 48 03 c8 48 8b c1 48 89 44 24 28 48 8b 4c 24 28 } //00 00 
	condition:
		any of ($a_*)
 
}