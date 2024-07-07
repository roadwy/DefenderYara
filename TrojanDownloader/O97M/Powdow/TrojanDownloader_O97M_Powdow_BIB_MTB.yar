
rule TrojanDownloader_O97M_Powdow_BIB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BIB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 62 76 2e 74 6e 65 69 6c 43 30 32 25 64 65 74 63 65 74 6f 72 50 2f 33 2f 6f 63 2e 68 63 6e 75 70 68 63 6e 69 70 2f 2f 3a } //1 sbv.tneilC02%detcetorP/3/oc.hcnuphcnip//:
		$a_01_1 = {49 45 58 28 24 54 43 7c 25 20 7b 2d 6a 6f 69 6e 28 24 5f 5b 2d 31 2e 2e 2d 24 5f 2e 4c 65 6e 67 74 68 5d 29 7d 29 3b 73 74 61 72 74 2d 70 72 6f 63 65 73 73 28 24 65 6e 76 3a 74 65 6d 70 2b 20 27 5c 6e 6f 74 65 70 61 64 2e 76 62 73 27 29 } //1 IEX($TC|% {-join($_[-1..-$_.Length])});start-process($env:temp+ '\notepad.vbs')
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}