
rule Worm_Win32_SillyShareCopy_V{
	meta:
		description = "Worm:Win32/SillyShareCopy.V,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 taskkill.exe
		$a_00_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00 } //1 DisableCMD
		$a_00_2 = {41 00 3a 00 5c 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 2e 00 73 00 63 00 72 00 } //2 A:\Passwords.scr
		$a_00_3 = {5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 48 00 69 00 64 00 64 00 65 00 6e 00 5c 00 4e 00 4f 00 48 00 49 00 44 00 44 00 45 00 4e 00 } //1 \Folder\Hidden\NOHIDDEN
		$a_01_4 = {4b 69 6c 6c 41 70 70 } //1 KillApp
		$a_01_5 = {62 65 61 74 72 65 6d 6f 76 61 62 6c 65 } //1 beatremovable
		$a_01_6 = {68 69 64 64 65 6e 66 6f 6c 64 65 72 } //1 hiddenfolder
		$a_01_7 = {72 61 72 61 64 64 65 64 } //1 raradded
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}