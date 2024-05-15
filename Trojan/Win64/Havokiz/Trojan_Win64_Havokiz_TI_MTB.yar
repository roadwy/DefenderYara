
rule Trojan_Win64_Havokiz_TI_MTB{
	meta:
		description = "Trojan:Win64/Havokiz.TI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 90 01 01 b8 90 01 04 48 6b c0 90 01 01 b9 90 01 04 48 6b c9 90 01 01 48 8b 54 24 90 01 01 4c 8b 90 01 01 24 90 01 01 41 8b 4c 08 90 01 01 8b 44 02 90 01 01 0b c1 35 90 01 04 39 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}