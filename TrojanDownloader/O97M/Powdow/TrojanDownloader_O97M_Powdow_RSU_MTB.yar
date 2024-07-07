
rule TrojanDownloader_O97M_Powdow_RSU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {77 77 77 2e 6d 69 6e 70 69 63 2e 64 65 2f 6b 2f 62 64 62 70 2f 31 36 67 6b 34 68 2f 27 90 0a 30 00 2e 49 6e 56 6f 6b 45 28 28 28 27 68 74 74 70 73 3a 2f 2f 90 00 } //1
		$a_00_1 = {53 68 65 6c 6c 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 49 60 45 58 20 28 28 6e 60 65 60 57 60 2d 4f 62 6a 60 45 60 63 60 54 20 28 28 27 4e 65 74 27 2b 27 2e 27 2b 27 57 65 62 63 27 2b 27 6c 69 65 6e 74 27 } //1 Shell "powershell I`EX ((n`e`W`-Obj`E`c`T (('Net'+'.'+'Webc'+'lient'
		$a_00_2 = {44 27 2b 27 6f 27 2b 27 77 27 2b 27 6e 27 2b 27 6c 27 2b 27 6f 27 2b 27 61 27 2b 27 64 27 2b 27 73 27 2b 27 74 72 69 27 } //1 D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'s'+'tri'
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}