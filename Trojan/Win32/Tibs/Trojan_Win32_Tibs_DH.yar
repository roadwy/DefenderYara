
rule Trojan_Win32_Tibs_DH{
	meta:
		description = "Trojan:Win32/Tibs.DH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 4d 08 8b 09 f7 d9 01 4d 0c 8b 45 0c } //01 00 
		$a_01_1 = {c9 c2 10 00 8d 05 } //01 00 
		$a_01_2 = {55 52 4c 00 00 00 49 73 4a 49 54 49 6e 50 72 6f } //01 00 
		$a_01_3 = {66 6f 45 78 41 00 00 00 47 6f 70 68 65 72 46 69 } //02 00 
		$a_01_4 = {55 69 53 74 6f 70 44 65 62 75 67 67 69 6e 67 00 00 00 4c 64 72 45 6e 75 6d 52 65 73 6f 75 72 63 } //00 00 
	condition:
		any of ($a_*)
 
}