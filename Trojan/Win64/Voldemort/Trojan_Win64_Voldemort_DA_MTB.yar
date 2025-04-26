
rule Trojan_Win64_Voldemort_DA_MTB{
	meta:
		description = "Trojan:Win64/Voldemort.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {56 6f 6c 64 65 6d 6f 72 74 5f 67 64 72 69 76 65 5f 63 2e 64 6c 6c } //10 Voldemort_gdrive_c.dll
		$a_81_1 = {53 70 61 72 6b 45 6e 74 72 79 50 6f 69 6e 74 } //1 SparkEntryPoint
		$a_81_2 = {73 68 65 65 74 73 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d } //1 sheets.googleapis.com
		$a_81_3 = {2f 75 70 6c 6f 61 64 2f 64 72 69 76 65 2f 76 33 2f 66 69 6c 65 73 3f 75 70 6c 6f 61 64 54 79 70 65 3d 6d 75 6c 74 69 70 61 72 74 } //1 /upload/drive/v3/files?uploadType=multipart
		$a_81_4 = {6e 2f 6f 61 75 74 68 32 2f 76 34 2f 74 6f 6b 65 6e } //1 n/oauth2/v4/token
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}