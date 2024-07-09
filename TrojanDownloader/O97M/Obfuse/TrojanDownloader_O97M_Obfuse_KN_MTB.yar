
rule TrojanDownloader_O97M_Obfuse_KN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 70 69 7a 2e 55 70 64 61 74 65 73 5c 73 74 6e 65 6d 75 63 6f 44 5c 22 29 } //1 = Environ$("USERPROFILE") & StrReverse("piz.Updates\stnemucoD\")
		$a_01_1 = {3d 20 53 68 65 6c 6c 28 53 74 61 72 74 75 70 2e 46 69 6c 65 73 31 2c 20 31 29 } //1 = Shell(Startup.Files1, 1)
		$a_03_2 = {3d 20 53 70 6c 69 74 28 42 74 2c 20 22 [0-01] 22 29 } //1
		$a_01_3 = {2e 43 6f 70 79 48 65 72 65 20 53 68 65 6c 6c 41 70 70 7a 7a 2e 4e 61 6d 65 73 70 61 63 65 28 50 61 74 68 7a 7a 29 2e 49 74 65 6d 73 } //1 .CopyHere ShellAppzz.Namespace(Pathzz).Items
		$a_01_4 = {26 20 53 74 72 52 65 76 65 72 73 65 28 22 70 69 7a 2e } //1 & StrReverse("piz.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}