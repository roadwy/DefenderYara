
rule Trojan_Win32_Vebzenpak_AF_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 6f 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } //DoFileDownload  3
		$a_80_1 = {50 77 64 43 68 61 6e 67 65 50 61 73 73 77 6f 72 64 41 } //PwdChangePasswordA  3
		$a_80_2 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 4e 61 6d 65 41 } //GetKeyboardLayoutNameA  3
		$a_80_3 = {53 6e 69 74 74 65 6e 64 65 } //Snittende  3
		$a_80_4 = {46 74 70 47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //FtpGetCurrentDirectoryA  3
		$a_80_5 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //gethostbyname  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}