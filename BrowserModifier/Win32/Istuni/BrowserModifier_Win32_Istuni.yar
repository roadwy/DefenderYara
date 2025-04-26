
rule BrowserModifier_Win32_Istuni{
	meta:
		description = "BrowserModifier:Win32/Istuni,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {4f 56 45 52 52 49 44 45 5f 46 4f 52 43 45 5f 45 4e 54 45 52 50 52 49 53 45 5f 49 4e 53 54 41 4c 4c 20 69 73 20 31 20 69 6e 20 73 65 74 74 69 6e 67 73 2e 68 2c 20 73 65 74 74 69 6e 67 20 66 6f 72 63 65 45 6e 74 65 72 70 72 69 73 65 49 6e 73 74 61 6c 6c 20 74 6f 20 74 72 75 65 } //2 OVERRIDE_FORCE_ENTERPRISE_INSTALL is 1 in settings.h, setting forceEnterpriseInstall to true
		$a_01_1 = {46 69 72 65 66 6f 78 20 77 69 6e 64 6f 77 20 63 61 70 74 75 72 65 64 2e 20 48 61 6e 64 6c 65 20 69 73 20 30 58 } //1 Firefox window captured. Handle is 0X
		$a_00_2 = {3a 5c 47 49 54 5c 61 64 64 6f 6e 49 6e 73 74 61 6c 6c 65 72 5c 69 6e 73 74 75 69 5c 52 65 6c 65 61 73 65 5c 69 6e 73 74 75 69 2e 70 64 62 } //2 :\GIT\addonInstaller\instui\Release\instui.pdb
		$a_00_3 = {46 69 72 65 66 6f 78 20 77 69 6e 64 6f 77 20 77 69 74 68 20 73 74 79 6c 65 20 30 78 39 36 30 30 30 30 30 30 20 63 61 70 74 75 72 65 64 20 28 41 64 64 20 65 78 74 65 6e 73 69 6f 6e 20 64 69 61 6c 6f 67 20 77 69 6e 64 6f 77 29 } //2 Firefox window with style 0x96000000 captured (Add extension dialog window)
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}