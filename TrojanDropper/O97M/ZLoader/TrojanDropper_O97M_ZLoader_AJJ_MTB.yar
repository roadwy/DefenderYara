
rule TrojanDropper_O97M_ZLoader_AJJ_MTB{
	meta:
		description = "TrojanDropper:O97M/ZLoader.AJJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 70 78 48 71 6a 6c 32 79 6d 4d 61 61 48 35 69 50 77 72 69 } //1 fpxHqjl2ymMaaH5iPwri
		$a_01_1 = {4b 55 70 47 66 53 41 46 64 33 6e 49 65 4c 6c } //1 KUpGfSAFd3nIeLl
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 43 56 52 37 37 31 31 2e 74 6d 70 2e 63 76 72 } //1 C:\Users\User\AppData\Local\Temp\CVR7711.tmp.cvr
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 77 63 74 38 33 37 2e 76 62 73 } //1 C:\Users\User\AppData\Local\Temp\wct837.vbs
		$a_01_4 = {72 67 71 32 67 35 33 } //1 rgq2g53
		$a_01_5 = {63 73 77 4e 76 5a 52 73 72 44 } //1 cswNvZRsrD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}