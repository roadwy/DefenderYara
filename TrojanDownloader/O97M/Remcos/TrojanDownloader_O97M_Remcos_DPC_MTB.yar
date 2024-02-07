
rule TrojanDownloader_O97M_Remcos_DPC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.DPC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 61 64 6c 6e 77 28 29 29 73 65 74 77 79 79 73 73 3d 69 77 78 6e 2e 6d 65 74 68 6f 64 73 5f 28 61 63 74 69 76 65 73 68 65 65 74 2e 70 61 67 65 73 65 74 75 70 2e 6c 65 66 74 68 65 61 64 65 72 29 2e 5f } //01 00  =createobject(adlnw())setwyyss=iwxn.methods_(activesheet.pagesetup.leftheader)._
		$a_01_1 = {3d 66 6b 6c 64 66 28 69 77 78 6e 2c 77 79 79 73 73 29 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e 6c 72 6c 6a 67 7a 28 29 } //01 00  =fkldf(iwxn,wyyss)endsubfunctionlrljgz()
		$a_01_2 = {67 67 67 2c 66 38 64 66 30 30 29 73 65 74 73 6a 74 6e 3d 67 67 67 2e 65 78 65 63 6d 65 74 68 6f 64 5f 28 7a 63 66 77 28 29 2c 66 38 64 66 30 30 29 65 6e 64 66 75 6e 63 74 69 6f 6e 70 72 69 76 61 74 65 66 75 6e 63 74 69 6f 6e 66 6a 6a 64 66 28 29 66 6a 6a 64 66 3d } //00 00  ggg,f8df00)setsjtn=ggg.execmethod_(zcfw(),f8df00)endfunctionprivatefunctionfjjdf()fjjdf=
	condition:
		any of ($a_*)
 
}