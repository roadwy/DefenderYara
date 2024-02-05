
rule Trojan_WinNT_Ramnit_gen_A{
	meta:
		description = "Trojan:WinNT/Ramnit.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {64 65 6d 65 74 72 61 5c 6c 6f 61 64 65 72 } //02 00 
		$a_01_1 = {68 56 72 6c 20 } //02 00 
		$a_01_2 = {0f b7 02 3d 4d 5a 00 00 75 02 eb 14 8b 0d } //02 00 
		$a_01_3 = {bf 22 00 00 c0 8b c6 41 f0 0f c1 08 8d 45 0c } //00 00 
	condition:
		any of ($a_*)
 
}