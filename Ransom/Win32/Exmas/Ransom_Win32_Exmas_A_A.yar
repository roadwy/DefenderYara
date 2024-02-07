
rule Ransom_Win32_Exmas_A_A{
	meta:
		description = "Ransom:Win32/Exmas.A.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7c 7c 64 6f 63 7c 7c 64 6f 63 62 7c 7c 64 6f 63 6d 7c 7c 64 6f 63 78 7c 7c 64 6f 74 7c 7c 64 6f 74 6d 7c 7c } //01 00  ||doc||docb||docm||docx||dot||dotm||
		$a_01_1 = {7c 7c 70 70 73 78 7c 7c 70 70 74 7c 7c 70 70 74 6d 7c 7c 70 70 74 78 7c 7c } //01 00  ||ppsx||ppt||pptm||pptx||
		$a_01_2 = {7c 7c 78 6c 73 7c 7c 78 6c 73 62 7c 7c 78 6c 73 6d 7c 7c 78 6c 73 78 7c 7c } //01 00  ||xls||xlsb||xlsm||xlsx||
		$a_01_3 = {25 75 73 65 72 69 64 25 } //01 00  %userid%
		$a_01_4 = {63 6d 64 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //00 00  cmd /c vssadmin delete shadows /all /quiet
		$a_00_5 = {5d 04 00 } //00 ff 
	condition:
		any of ($a_*)
 
}