
rule TrojanDownloader_O97M_Pogleggis_A{
	meta:
		description = "TrojanDownloader:O97M/Pogleggis.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = VBA.CreateObject("WScript.Shell")
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 = CreateObject("ADODB.Stream")
		$a_01_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } //1 .Open "GET",
		$a_01_3 = {3d 20 53 68 65 6c 6c 28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 77 6f 72 64 2e 65 78 65 22 2c } //1 = Shell(Environ("TEMP") & "\word.exe",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}