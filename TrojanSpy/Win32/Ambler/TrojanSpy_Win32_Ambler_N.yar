
rule TrojanSpy_Win32_Ambler_N{
	meta:
		description = "TrojanSpy:Win32/Ambler.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {59 33 c9 85 c0 7e 09 80 34 31 90 01 01 41 3b c8 7c f7 5e c3 90 00 } //02 00 
		$a_01_1 = {45 47 49 6e 6a 65 63 74 5f 44 4c 4c 2e 64 6c 6c 00 47 6d 4d 79 49 6e 69 74 50 6f 69 6e 74 00 47 6d 57 72 69 74 65 52 65 67 41 6e 64 49 6d 70 6f 72 74 00 49 6e 6a 65 63 74 50 72 6f 63 65 73 73 00 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 66 69 6c 65 73 2f 25 73 25 73 2f } //01 00  http://%s/files/%s%s/
		$a_01_3 = {4f 72 64 65 72 5f 73 65 6c 2e 70 68 70 3f 43 6f 6f 6b 69 65 3d 4d 41 43 7c } //00 00  Order_sel.php?Cookie=MAC|
	condition:
		any of ($a_*)
 
}