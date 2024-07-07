
rule Trojan_Win32_Reline_AMH_MTB{
	meta:
		description = "Trojan:Win32/Reline.AMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {4a 6f 68 6e 44 6f 65 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 } //JohnDoe\Start Menu\Programs  3
		$a_80_1 = {25 25 50 3a 68 69 64 63 6f 6e 3a } //%%P:hidcon:  3
		$a_80_2 = {73 76 63 68 6f 73 74 2e 63 6d 64 } //svchost.cmd  3
		$a_80_3 = {40 49 6e 73 74 61 6c 6c 45 6e 64 40 21 } //@InstallEnd@!  3
		$a_80_4 = {45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 } //Enter password  3
		$a_80_5 = {21 52 65 71 75 69 72 65 20 57 69 6e 64 6f 77 73 } //!Require Windows  3
		$a_80_6 = {47 65 74 4e 61 74 69 76 65 53 79 73 74 65 6d 49 6e 66 6f } //GetNativeSystemInfo  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}