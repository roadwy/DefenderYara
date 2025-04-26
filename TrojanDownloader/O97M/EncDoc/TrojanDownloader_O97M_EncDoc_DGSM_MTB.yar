
rule TrojanDownloader_O97M_EncDoc_DGSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.DGSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 64 68 76 64 79 6b 61 72 64 3d 74 66 74 6a 69 2e 6f 70 65 6e 74 65 78 74 66 69 6c 65 28 72 70 6b 6b 2b 22 5c 61 6e 7a 77 73 2e 76 62 73 22 2c 38 2c 74 72 75 65 29 } //1 setdhvdykard=tftji.opentextfile(rpkk+"\anzws.vbs",8,true)
		$a_01_1 = {6c 78 61 67 3d 76 71 6c 7a 68 62 2e 6f 70 65 6e 28 66 35 66 67 30 65 2b 22 5c 61 6e 7a 77 73 2e 76 62 73 22 29 } //1 lxag=vqlzhb.open(f5fg0e+"\anzws.vbs")
		$a_01_2 = {76 6e 6a 65 72 3d 22 61 70 70 64 61 74 61 22 } //1 vnjer="appdata"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}