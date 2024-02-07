
rule TrojanDownloader_O97M_EncDoc_PABA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PABA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {65 28 29 64 69 6d 79 6d 62 64 74 72 2c 6d 79 64 6f 63 73 70 61 74 68 2c 66 65 67 64 6e 2c 76 63 66 65 67 64 6e 3d 72 61 6e 67 65 28 22 61 31 30 35 22 29 2e 76 61 6c 75 65 2b 22 22 2b 72 61 6e 67 65 28 22 61 31 30 34 22 29 2e 76 61 6c 75 65 2b 72 61 6e 67 65 28 22 61 31 30 33 22 29 2e 76 61 6c 75 65 2b 22 2d 22 2b 72 61 6e 67 65 28 22 61 31 30 30 22 29 2e 76 61 6c 75 65 79 6d 62 64 74 72 3d 63 77 79 6e 28 29 2b 22 5c 63 71 6a 6a 71 2e 62 61 } //01 00  e()dimymbdtr,mydocspath,fegdn,vcfegdn=range("a105").value+""+range("a104").value+range("a103").value+"-"+range("a100").valueymbdtr=cwyn()+"\cqjjq.ba
		$a_01_1 = {76 63 3d 66 6d 77 6f 6a 68 6d 61 6a 28 63 77 79 6e 28 29 29 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e 66 6d 77 6f 6a 68 6d 61 6a 28 76 30 64 66 29 73 65 74 67 73 67 61 3d 67 65 74 6f 62 6a 65 63 74 28 72 61 6e 67 65 28 22 61 31 30 36 22 29 2e 76 61 6c 75 65 29 62 64 66 64 66 3d 67 73 67 61 2e 6f 70 65 6e 28 76 30 64 66 2b 22 5c 63 71 6a 6a 71 2e 62 61 74 22 29 65 6e 64 66 75 6e 63 74 69 6f 6e 70 72 69 76 61 74 65 66 75 6e 63 74 69 6f 6e 63 77 79 6e 28 29 63 77 79 6e 3d 65 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 65 } //00 00  vc=fmwojhmaj(cwyn())endsubfunctionfmwojhmaj(v0df)setgsga=getobject(range("a106").value)bdfdf=gsga.open(v0df+"\cqjjq.bat")endfunctionprivatefunctioncwyn()cwyn=environ("appdata")e
	condition:
		any of ($a_*)
 
}