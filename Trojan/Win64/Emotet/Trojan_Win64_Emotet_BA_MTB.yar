
rule Trojan_Win64_Emotet_BA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cb 48 8d 7f 90 01 01 f7 eb 90 02 04 ff c3 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 8b 05 90 01 04 48 63 d1 0f b6 0c 02 32 4c 3e 90 01 01 88 4f 90 01 01 49 ff cf 75 90 00 } //01 00 
		$a_03_1 = {f7 ef c1 fa 90 01 01 83 c7 90 01 01 8b c2 c1 e8 90 01 01 03 d0 48 8b 05 90 01 04 48 63 d2 48 6b d2 90 01 01 48 03 d0 41 8a 04 10 41 32 04 34 88 06 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}