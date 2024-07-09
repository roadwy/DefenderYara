
rule TrojanDownloader_O97M_Powdow_RPA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RPA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 6f 6e 74 6f 73 6f 66 6f 72 72 65 73 74 65 72 64 65 6d 6f 2e 62 6c 6f 62 2e 63 6f 72 65 2e 77 69 6e 64 6f 77 73 2e 6e 65 74 2f 64 6f 63 73 2f 6c 6f 61 64 65 72 6f 75 74 6f 6e 65 6c 69 6e 65 72 2e 70 73 31 27 29 29 90 0a 9f 00 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f } //1
		$a_01_1 = {73 68 65 6c 6c 22 70 6f 77 65 72 73 68 65 6c 6c 2d 77 68 69 64 64 65 6e 2d 65 78 65 63 62 79 70 61 73 73 69 6e 76 6f 6b 65 2d 65 78 70 72 65 73 73 69 6f 6e 28 28 6e 65 77 2d 6f 62 6a 65 63 74 73 79 73 74 65 6d 2e 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e } //1 shell"powershell-whidden-execbypassinvoke-expression((new-objectsystem.net.webclient).
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}