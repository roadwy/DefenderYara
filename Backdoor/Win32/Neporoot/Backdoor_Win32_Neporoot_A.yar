
rule Backdoor_Win32_Neporoot_A{
	meta:
		description = "Backdoor:Win32/Neporoot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {b9 3f 00 00 00 33 c0 8d 7c 24 ?? 8d 54 24 ?? f3 ab 66 ab aa bf ?? ?? ?? ?? 83 c9 ff 33 c0 53 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa 8d 54 24 ?? c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d bc 24 } //2
		$a_01_1 = {2e 75 65 6f 70 65 6e 2e 63 6f 6d 2f 74 65 73 74 2e 68 74 6d 6c } //1 .ueopen.com/test.html
		$a_01_2 = {2a 28 53 59 29 23 20 63 6d 64 } //1 *(SY)# cmd
		$a_01_3 = {73 65 6e 64 20 3d 20 25 64 } //1 send = %d
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}