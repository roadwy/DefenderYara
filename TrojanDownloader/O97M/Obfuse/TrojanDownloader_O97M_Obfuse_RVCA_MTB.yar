
rule TrojanDownloader_O97M_Obfuse_RVCA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 6f 62 6a 65 63 74 28 66 6c 6f 72 69 73 74 29 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 65 61 72 72 69 6e 67 73 29 2e 72 75 6e 68 6f 75 73 65 68 6f 6c 64 73 } //01 00  getobject(florist).createobject(earrings).runhouseholds
		$a_01_1 = {3d 63 68 72 28 28 37 2a 32 29 2b 28 28 28 31 30 2d 34 29 2a 32 29 2a 32 29 29 26 63 68 72 28 28 28 28 31 36 2f 32 29 2a 32 29 2b 28 34 2a 35 29 29 2a 32 29 26 6d 69 64 28 6e 75 72 73 65 73 2c 69 2b 31 2c 32 29 69 3d 69 2b 32 } //01 00  =chr((7*2)+(((10-4)*2)*2))&chr((((16/2)*2)+(4*5))*2)&mid(nurses,i+1,2)i=i+2
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 64 65 6d 6f 63 72 61 74 73 6d 69 6e 6e 65 61 70 6f 6c 69 73 28 73 68 65 65 74 73 28 22 66 32 63 61 22 29 2e 72 61 6e 67 65 28 22 68 31 38 32 22 29 2e 76 61 6c 75 65 29 } //00 00  workbook_open()democratsminneapolis(sheets("f2ca").range("h182").value)
	condition:
		any of ($a_*)
 
}