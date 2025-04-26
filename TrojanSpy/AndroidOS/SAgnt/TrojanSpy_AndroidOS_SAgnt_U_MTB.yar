
rule TrojanSpy_AndroidOS_SAgnt_U_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 44 6f 6e 65 43 61 70 74 75 72 69 6e 67 41 6c 6c 50 68 6f 74 6f 73 } //1 onDoneCapturingAllPhotos
		$a_01_1 = {73 71 75 61 72 65 64 65 76 61 70 70 73 2e 63 6f 6d 2f 73 63 6f 72 69 6e 67 73 65 72 76 69 63 65 2f 6e 65 77 53 65 72 76 69 63 65 2e 70 68 70 } //5 squaredevapps.com/scoringservice/newService.php
		$a_01_2 = {67 65 74 53 4d 53 44 61 74 61 } //1 getSMSData
		$a_01_3 = {67 65 74 43 61 6c 6c 4c 6f 67 73 } //1 getCallLogs
		$a_01_4 = {47 50 53 54 72 61 63 6b 65 72 } //1 GPSTracker
		$a_01_5 = {73 71 75 61 72 65 2e 6e 61 64 72 61 2e 74 61 78 2e 74 61 78 69 6e 66 6f } //5 square.nadra.tax.taxinfo
		$a_01_6 = {53 65 6e 64 44 61 74 61 } //1 SendData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1) >=14
 
}