
rule Trojan_Win64_Rovnix{
	meta:
		description = "Trojan:Win64/Rovnix,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {0f be 44 24 30 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 0f be 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 eb bc } //02 00 
		$a_00_1 = {0f b7 44 24 30 48 8b 4c 24 20 48 8b 14 24 0f b7 0c 51 33 c8 8b c1 48 8b 4c 24 20 48 8b 14 24 66 89 04 51 eb c5 } //02 00 
		$a_01_2 = {42 4f 4f 54 4b 49 54 5f 44 4c 4c } //01 00 
		$a_01_3 = {42 4e 32 31 52 63 30 4c 71 5a 41 39 } //00 00 
		$a_00_4 = {5d 04 00 } //00 20 
	condition:
		any of ($a_*)
 
}