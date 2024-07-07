
rule PWS_Win32_Lmir_AGZ{
	meta:
		description = "PWS:Win32/Lmir.AGZ,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //10 SOFTWARE\Borland\Delphi
		$a_01_1 = {53 6e 61 70 73 68 6f 74 00 00 00 00 48 65 61 70 } //3
		$a_01_2 = {6d 69 72 32 00 00 54 46 72 6d 4d 61 69 6e 00 } //3
		$a_01_3 = {54 54 72 6f 79 4d 69 72 } //1 TTroyMir
		$a_01_4 = {2e 61 73 70 3f 55 73 65 72 50 57 44 3d } //1 .asp?UserPWD=
		$a_01_5 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_01_6 = {57 6f 6f 6f 6c } //1 Woool
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=18
 
}