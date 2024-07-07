
rule PWS_Win32_Zhengtu_B{
	meta:
		description = "PWS:Win32/Zhengtu.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 44 8b 4c 24 30 83 c4 18 8d 54 24 14 c6 44 24 10 4d c6 44 24 11 5a } //1
		$a_01_1 = {63 6d 64 20 2f 63 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 53 74 20 25 73 } //1 cmd /c rundll32.exe %s St %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}