
rule TrojanDownloader_O97M_Powdow_RPWD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RPWD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 33 38 2e 32 30 31 2e 31 34 39 2e 34 33 2f 90 02 1f 2f 90 02 07 2e 70 73 31 27 29 90 00 } //1
		$a_01_1 = {3d 63 72 65 61 74 65 70 72 6f 63 65 73 73 61 28 30 26 2c 63 68 72 28 31 31 32 29 2b 22 6f 77 65 72 22 2b 22 73 68 65 6c 6c 2e 65 78 65 22 2b 63 68 72 28 31 35 30 29 2b 22 77 69 6e 64 6f 77 73 74 79 6c 65 68 69 64 64 65 6e 22 2b 22 69 65 78 28 6e 65 77 2d 6f 62 6a 65 63 74 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f } //1 =createprocessa(0&,chr(112)+"ower"+"shell.exe"+chr(150)+"windowstylehidden"+"iex(new-objectnet.webclient).downloadstring('http://
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}