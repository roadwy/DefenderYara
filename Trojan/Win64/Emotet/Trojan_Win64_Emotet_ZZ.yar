
rule Trojan_Win64_Emotet_ZZ{
	meta:
		description = "Trojan:Win64/Emotet.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be 90 01 01 03 d0 41 2b d0 49 ff 90 01 01 90 03 05 08 44 8b c2 45 8a 45 8a 90 01 01 44 8b c2 90 00 } //0a 00 
		$a_03_2 = {41 8b c0 45 84 90 01 01 75 d8 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 31 17 05 80 5c 30 00 00 32 17 05 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}