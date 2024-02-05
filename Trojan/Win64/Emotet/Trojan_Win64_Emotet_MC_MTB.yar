
rule Trojan_Win64_Emotet_MC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c3 ff c3 6b d2 90 01 01 2b c2 48 63 d0 48 8b 05 90 01 04 8a 14 02 41 32 14 3c 88 17 90 00 } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}