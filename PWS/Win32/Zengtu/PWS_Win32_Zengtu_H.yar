
rule PWS_Win32_Zengtu_H{
	meta:
		description = "PWS:Win32/Zengtu.H,SIGNATURE_TYPE_PEHSTR_EXT,16 00 14 00 11 00 00 02 00 "
		
	strings :
		$a_00_0 = {7a 68 65 6e 67 74 75 5f 63 6c 69 65 6e 74 } //01 00  zhengtu_client
		$a_01_1 = {75 73 65 72 3d } //02 00  user=
		$a_01_2 = {26 70 61 73 73 3d } //01 00  &pass=
		$a_01_3 = {26 73 65 72 3d } //01 00  &ser=
		$a_01_4 = {26 70 61 73 73 32 3d } //02 00  &pass2=
		$a_01_5 = {26 62 65 69 7a 68 75 3d } //02 00  &beizhu=
		$a_01_6 = {26 70 63 6e 61 6d 65 3d } //02 00  &pcname=
		$a_01_7 = {53 65 6e 64 20 4f 4b } //01 00  Send OK
		$a_01_8 = {26 63 61 6e 67 6b 75 3d } //02 00  &cangku=
		$a_00_9 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_01_10 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_01_11 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_12 = {44 6f 77 6e 44 4c 4c 2e 64 6c 6c } //02 00  DownDLL.dll
		$a_01_13 = {53 74 61 72 74 48 6f 6f 6b } //02 00  StartHook
		$a_01_14 = {72 69 73 69 4f 66 66 } //02 00  risiOff
		$a_01_15 = {72 69 73 69 4f 6e } //02 00  risiOn
		$a_01_16 = {73 68 69 7a 6f 6e 67 72 69 73 69 6e 69 } //00 00  shizongrisini
	condition:
		any of ($a_*)
 
}