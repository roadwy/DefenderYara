
rule Trojan_Win64_Winnti_Z_dha{
	meta:
		description = "Trojan:Win64/Winnti.Z!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 0f b6 0b ff c2 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff 3b 90 01 01 72 90 00 } //01 00 
		$a_03_1 = {8b 0e 49 03 cc e8 90 01 04 41 3b c5 74 90 00 } //01 00 
		$a_01_2 = {0f b6 11 33 c0 84 d2 74 1c 0f 1f 80 00 00 00 00 69 c0 83 00 00 00 0f be d2 48 ff c1 03 c2 0f b6 11 84 d2 } //01 00 
		$a_01_3 = {41 70 70 69 6e 69 74 36 34 2e 64 6c 6c } //00 00  Appinit64.dll
	condition:
		any of ($a_*)
 
}