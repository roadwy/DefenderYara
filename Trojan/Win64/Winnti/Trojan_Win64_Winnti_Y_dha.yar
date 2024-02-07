
rule Trojan_Win64_Winnti_Y_dha{
	meta:
		description = "Trojan:Win64/Winnti.Y!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 63 d0 43 8d 0c 01 41 ff c0 42 32 0c 1a 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 42 88 04 1a 44 3b 03 72 de } //01 00 
		$a_03_1 = {8b 0e 49 03 cc e8 90 01 04 41 3b c5 74 90 00 } //01 00 
		$a_01_2 = {69 c0 83 00 00 00 0f be d2 03 c2 48 ff c1 8a 11 84 d2 75 ec 0f ba f0 1f c3 } //01 00 
		$a_03_3 = {ff d8 ff e0 00 00 00 00 00 00 90 02 64 e9 ea eb ec ed ee ef f0 90 00 } //01 00 
		$a_01_4 = {73 74 6f 6e 65 36 34 2e 64 6c 6c } //00 00  stone64.dll
	condition:
		any of ($a_*)
 
}