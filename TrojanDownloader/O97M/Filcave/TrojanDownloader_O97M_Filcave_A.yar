
rule TrojanDownloader_O97M_Filcave_A{
	meta:
		description = "TrojanDownloader:O97M/Filcave.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 65 6d 70 4c 69 6e 6b 46 69 6e 61 6c 20 3d 20 58 6f 72 43 28 43 61 6c 63 46 69 76 65 2c 20 31 33 33 37 29 20 26 20 54 65 6d 70 43 6f 6c 6f 6e 20 26 20 46 75 63 6b 54 77 6f 20 26 } //1 TempLinkFinal = XorC(CalcFive, 1337) & TempColon & FuckTwo &
	condition:
		((#a_01_0  & 1)*1) >=1
 
}