
rule Backdoor_Win32_Soeda_A_dha{
	meta:
		description = "Backdoor:Win32/Soeda.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3c 21 2d 2d 3f 2a 24 40 } //1 <!--?*$@
		$a_01_1 = {52 61 6e 67 65 3a 20 62 79 74 65 73 3d 25 64 2d } //1 Range: bytes=%d-
		$a_01_2 = {72 65 73 75 6c 74 3f 73 69 64 3d } //1 result?sid=
		$a_01_3 = {77 69 6e 33 32 2e 25 64 2e 25 64 2e 25 64 2e 25 64 2e 25 64 2e 25 73 } //1 win32.%d.%d.%d.%d.%d.%s
		$a_01_4 = {7c 25 75 7c 25 75 7c 25 75 7c 25 75 7c 25 75 } //1 |%u|%u|%u|%u|%u
		$a_01_5 = {6d 69 63 72 6f 73 6f 66 74 73 65 72 76 69 63 65 73 2e 70 72 6f 78 79 64 6e 73 2e 63 6f 6d } //1 microsoftservices.proxydns.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}