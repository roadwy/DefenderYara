
rule TrojanDownloader_O97M_Obfuse_NV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 79 70 65 72 58 20 3d 20 48 79 70 65 72 58 20 2b 20 30 2e } //1 HyperX = HyperX + 0.
		$a_01_1 = {4e 47 70 6f 77 65 72 20 3d } //1 NGpower =
		$a_01_2 = {63 3a 5c 48 65 6c 70 65 72 65 73 5c 42 4a 4b 47 4a 47 79 66 79 67 68 75 36 37 35 37 38 35 36 37 34 37 38 36 2e 62 61 74 22 2c 20 54 72 75 65 } //1 c:\Helperes\BJKGJGyfyghu675785674786.bat", True
		$a_01_3 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 39 31 2f 67 6f 64 7a 2f 34 66 7a 61 73 2e 65 5e 22 29 } //1 a.WriteLine ("91/godz/4fzas.e^")
		$a_01_4 = {22 47 65 72 69 6c 61 78 2e 65 5e 22 } //1 "Gerilax.e^"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}