
rule PWS_Win32_Delmes_A{
	meta:
		description = "PWS:Win32/Delmes.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {17 00 00 00 6d 61 69 6c 2f 49 6e 62 6f 78 4c 69 67 68 74 2e 61 73 70 78 3f 6e 3d 00 } //1
		$a_00_1 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //1 WshShell.Run "rundll32.exe shell32.dll,Control_RunDLL
		$a_01_2 = {bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}