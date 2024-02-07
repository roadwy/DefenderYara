
rule Trojan_Win32_Rutery_A{
	meta:
		description = "Trojan:Win32/Rutery.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_02_0 = {c7 05 30 80 40 00 00 00 00 00 89 5c 24 04 c7 04 24 90 01 04 e8 c0 e8 ff ff 81 3d 30 80 40 00 95 5f 00 00 7e da 90 00 } //05 00 
		$a_02_1 = {89 c1 c1 e9 10 a9 80 80 00 00 0f 44 c1 8d 4a 02 0f 44 d1 00 c0 83 da 03 66 c7 02 90 01 02 89 da 8b 0a 90 00 } //02 00 
		$a_01_2 = {75 6c 74 69 6d 61 74 65 2d 72 65 63 6f 76 65 72 79 2e 70 6c } //02 00  ultimate-recovery.pl
		$a_01_3 = {6c 69 62 54 55 52 2e 64 6c 6c } //00 00  libTUR.dll
	condition:
		any of ($a_*)
 
}