
rule Backdoor_BAT_Bladabindi_ABQ_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {06 07 6f 27 90 01 02 0a 17 73 90 01 03 0a 0c 08 02 16 02 8e 69 6f 90 01 03 0a 08 6f 90 01 03 0a 06 6f 90 01 03 0a 0d 09 2a 90 00 } //5
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {65 30 39 75 41 76 5a 36 51 } //1 e09uAvZ6Q
		$a_01_4 = {48 74 74 70 52 65 73 70 6f 6e 73 65 } //1 HttpResponse
		$a_01_5 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}