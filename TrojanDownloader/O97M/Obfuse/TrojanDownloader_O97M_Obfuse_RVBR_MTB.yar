
rule TrojanDownloader_O97M_Obfuse_RVBR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 6f 62 6a 65 63 74 28 6e 75 74 66 66 28 22 31 34 36 31 33 32 31 33 37 31 33 36 31 33 30 31 33 36 31 34 33 31 34 32 30 38 35 22 29 29 } //1 getobject(nutff("146132137136130136143142085"))
		$a_01_1 = {61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 6e 61 6d 65 3c 3e 6e 75 74 66 66 28 22 30 37 36 30 37 36 30 37 33 31 32 37 31 33 38 31 32 36 22 29 } //1 activedocument.name<>nutff("076076073127138126")
		$a_01_2 = {63 68 72 28 62 65 65 74 73 2d 32 37 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 chr(beets-27)endfunction
		$a_01_3 = {6c 6f 6f 70 77 68 69 6c 65 6c 65 6e 28 6d 69 6c 6b 29 3e 30 6e 75 74 66 66 3d 6f 61 74 6d 69 6c 6b 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 loopwhilelen(milk)>0nutff=oatmilkendfunction
		$a_01_4 = {61 75 74 6f 6f 70 65 6e 28 29 6d 79 6d 61 63 72 6f 65 6e 64 73 75 62 } //1 autoopen()mymacroendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}