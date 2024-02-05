
rule Trojan_Win32_AutoRun_BFC_MTB{
	meta:
		description = "Trojan:Win32/AutoRun.BFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {5b 61 75 74 6f 72 75 6e 5d } //[autorun]  01 00 
		$a_00_1 = {73 68 65 6c 6c 5c 53 65 61 72 63 68 2e 2e 2e 5c 63 6f 6d 6d 61 6e 64 3d 4d 79 5f 4d 75 73 69 63 2e 65 78 65 20 3a 3a 7b 31 66 34 64 65 33 37 30 2d 64 36 32 37 2d 31 31 64 31 2d 62 61 34 66 2d 30 30 61 30 63 39 31 65 65 64 62 61 7d } //01 00 
		$a_80_2 = {73 68 65 6c 6c 5c 44 65 6c 65 74 65 20 56 69 72 75 73 65 73 } //shell\Delete Viruses  01 00 
		$a_80_3 = {49 44 76 44 46 6f 6c 64 65 72 74 56 69 65 77 } //IDvDFoldertView  01 00 
		$a_80_4 = {49 20 53 6f 66 74 77 61 72 65 } //I Software  01 00 
		$a_80_5 = {43 72 65 61 74 65 64 20 42 79 20 44 2e 49 73 68 61 6e 20 48 61 72 73 68 61 6e 61 } //Created By D.Ishan Harshana  01 00 
		$a_80_6 = {49 63 6f 6e 41 72 65 61 5f 49 6d 61 67 65 3d 49 73 68 61 6e 42 67 2e 69 73 68 } //IconArea_Image=IshanBg.ish  01 00 
		$a_80_7 = {50 68 6f 74 6f 73 2e 65 78 65 } //Photos.exe  00 00 
	condition:
		any of ($a_*)
 
}