
rule TrojanDownloader_O97M_Obfuse_AB_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AB!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 32 2e 54 65 78 74 } //1 = UserForm1.TextBox2.Text
		$a_02_1 = {3d 20 43 75 72 44 69 72 20 26 20 43 68 72 28 39 32 29 20 26 20 90 02 06 20 26 20 22 2e 6a 73 90 00 } //1
		$a_02_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 10 2c 20 54 72 75 65 2c 20 54 72 75 65 29 90 00 } //1
		$a_00_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 = CreateObject("Shell.Application")
		$a_00_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 .ShellExecute
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}