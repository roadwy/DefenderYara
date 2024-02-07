
rule Trojan_Win32_Killav_EI{
	meta:
		description = "Trojan:Win32/Killav.EI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 36 30 53 61 66 65 2e 65 78 65 00 90 03 06 05 53 79 73 54 65 6d 44 69 6b 6f 75 90 00 } //01 00 
		$a_00_1 = {5a 68 75 44 6f 6e 67 46 61 6e 67 59 75 2e 65 78 65 } //01 00  ZhuDongFangYu.exe
		$a_03_2 = {8a 0c 02 80 c1 90 01 01 88 08 40 4e 75 f4 5e c3 90 00 } //01 00 
		$a_03_3 = {68 e0 2e 00 00 e8 90 01 04 e8 90 01 04 68 10 27 00 00 e8 90 01 04 6a 00 6a 00 6a 00 68 90 01 04 6a 00 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}