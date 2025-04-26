
rule Ransom_Win32_LockScreen_AR{
	meta:
		description = "Ransom:Win32/LockScreen.AR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //3 taskkill /F /IM taskmgr.exe
		$a_01_1 = {20 00 79 00 63 00 3b 04 79 00 33 04 79 00 2c 00 20 00 42 00 61 00 3c 04 20 00 3d 04 65 00 6f 00 } //4  ycлyгy, Baм нeo
		$a_01_2 = {42 00 48 00 18 04 4d 00 41 00 48 00 18 04 45 00 21 00 21 00 00 } //3
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=10
 
}