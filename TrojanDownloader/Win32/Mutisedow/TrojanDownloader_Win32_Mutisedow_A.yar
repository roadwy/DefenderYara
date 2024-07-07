
rule TrojanDownloader_Win32_Mutisedow_A{
	meta:
		description = "TrojanDownloader:Win32/Mutisedow.A,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 64 6f 77 73 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 73 74 61 6c 6c 65 72 22 29 } //CreateObject("WindowsInstaller.Installer")  2
		$a_80_1 = {55 49 4c 65 76 65 6c 3d 32 } //UILevel=2  2
		$a_80_2 = {49 6e 73 74 61 6c 6c 50 72 6f 64 75 63 74 22 68 74 74 70 } //InstallProduct"http  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}