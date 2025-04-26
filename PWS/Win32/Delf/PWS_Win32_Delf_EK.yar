
rule PWS_Win32_Delf_EK{
	meta:
		description = "PWS:Win32/Delf.EK,SIGNATURE_TYPE_PEHSTR,34 00 34 00 09 00 00 "
		
	strings :
		$a_01_0 = {65 6d 61 69 6c 3d 69 6b 73 72 30 78 73 70 40 67 6d 61 69 6c 2e 63 6f 6d } //10 email=iksr0xsp@gmail.com
		$a_01_1 = {65 6d 61 69 6c 3d 69 6b 73 2e 65 78 65 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //10 email=iks.exe@hotmail.com
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //10 GetKeyNameTextA
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 2f 33 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 49 6e 64 79 20 4c 69 62 72 61 72 79 29 } //10 Mozilla/3.0 (compatible; Indy Library)
		$a_01_5 = {2f 65 6e 76 69 61 2e 70 68 70 } //10 /envia.php
		$a_01_6 = {46 61 6c 68 61 20 6e 61 20 63 6f 6e 65 78 } //2 Falha na conex
		$a_01_7 = {73 75 62 6a 65 63 74 3d } //1 subject=
		$a_01_8 = {6d 65 73 73 61 67 65 3d } //1 message=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=52
 
}