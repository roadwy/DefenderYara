
rule Ransom_Win32_Exmas_A_{
	meta:
		description = "Ransom:Win32/Exmas.A!!Exmas.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {7c 7c 64 6f 63 7c 7c 64 6f 63 62 7c 7c 64 6f 63 6d 7c 7c 64 6f 63 78 7c 7c 64 6f 74 7c 7c 64 6f 74 6d 7c 7c } //1 ||doc||docb||docm||docx||dot||dotm||
		$a_01_1 = {7c 7c 70 70 73 78 7c 7c 70 70 74 7c 7c 70 70 74 6d 7c 7c 70 70 74 78 7c 7c } //1 ||ppsx||ppt||pptm||pptx||
		$a_01_2 = {7c 7c 78 6c 73 7c 7c 78 6c 73 62 7c 7c 78 6c 73 6d 7c 7c 78 6c 73 78 7c 7c } //1 ||xls||xlsb||xlsm||xlsx||
		$a_01_3 = {63 6d 64 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 cmd /c vssadmin delete shadows /all /quiet
		$a_01_4 = {50 41 59 20 54 4f 20 52 45 43 4f 56 45 52 20 59 4f 55 52 20 44 41 54 41 } //1 PAY TO RECOVER YOUR DATA
		$a_01_5 = {43 68 61 6e 67 65 64 46 69 6c 65 45 78 74 3a } //1 ChangedFileExt:
		$a_01_6 = {44 65 66 61 75 6c 74 43 72 79 70 74 4b 65 79 3a } //1 DefaultCryptKey:
		$a_01_7 = {69 73 43 72 79 70 74 46 69 6c 65 4e 61 6d 65 73 3a } //1 isCryptFileNames:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}