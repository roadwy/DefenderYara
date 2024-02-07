
rule Adware_Win32_Vidsaver{
	meta:
		description = "Adware:Win32/Vidsaver,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 69 64 2d 53 61 76 65 72 2d 42 68 6f 2e 74 78 74 } //01 00  Vid-Saver-Bho.txt
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 56 69 64 2d 53 61 76 65 72 5c } //01 00  Software\Vid-Saver\
		$a_02_2 = {46 6f 72 63 65 52 65 6d 6f 76 65 20 7b 90 01 24 7d 20 3d 20 73 20 27 56 69 64 2d 53 61 76 65 72 27 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}