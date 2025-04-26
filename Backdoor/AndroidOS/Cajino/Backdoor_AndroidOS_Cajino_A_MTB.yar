
rule Backdoor_AndroidOS_Cajino_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Cajino.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 72 65 61 74 65 43 6f 6e 74 61 63 74 46 69 6c 65 } //1 createContactFile
		$a_00_1 = {64 65 6c 65 74 54 65 6d 70 46 69 6c 65 } //1 deletTempFile
		$a_00_2 = {63 61 6c 6c 5f 6c 6f 67 } //1 call_log
		$a_00_3 = {75 70 6c 6f 61 64 5f 6d 65 73 73 61 67 65 } //1 upload_message
		$a_00_4 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 69 6e 67 49 6e 66 6f } //1 FileDownloadingInfo
		$a_01_5 = {45 58 54 52 41 5f 45 58 54 52 41 20 3d } //1 EXTRA_EXTRA =
		$a_00_6 = {3e 3e 3e 20 52 65 63 65 69 76 65 20 69 6e 74 65 6e 74 3a } //1 >>> Receive intent:
		$a_00_7 = {63 61 2f 6a 69 2f 6e 6f } //3 ca/ji/no
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*3) >=6
 
}