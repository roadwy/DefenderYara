
rule Trojan_Win32_Koobface_gen_H{
	meta:
		description = "Trojan:Win32/Koobface.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {75 22 8b c7 c6 06 25 8b 0d 90 01 04 46 c1 e8 04 8a 04 08 88 06 90 00 } //01 00 
		$a_01_1 = {64 75 6d 70 2e 70 68 70 3f 76 3d } //01 00  dump.php?v=
		$a_01_2 = {6c 2e 70 68 70 3f 75 3d 25 73 00 } //01 00 
		$a_01_3 = {42 65 20 63 61 72 65 66 75 6c } //01 00  Be careful
		$a_01_4 = {2f 63 68 65 63 6b 2f } //00 00  /check/
	condition:
		any of ($a_*)
 
}