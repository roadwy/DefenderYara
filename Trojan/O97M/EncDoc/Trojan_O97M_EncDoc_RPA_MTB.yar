
rule Trojan_O97M_EncDoc_RPA_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RPA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 59 53 44 73 20 2b 20 22 5c 47 47 53 51 69 2e 76 62 73 22 2c 20 38 2c 20 54 72 75 65 29 } //1 .OpenTextFile(YSDs + "\GGSQi.vbs", 8, True)
		$a_01_1 = {3d 20 47 65 74 54 69 63 6b 43 6f 75 6e 74 20 2b 20 28 46 69 6e 69 73 68 20 2a 20 31 30 30 30 29 } //1 = GetTickCount + (Finish * 1000)
		$a_03_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 0a 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}