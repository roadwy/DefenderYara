
rule TrojanDownloader_Win32_Banload_AQS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQS,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 44 30 37 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //1
		$a_01_1 = {73 6d 00 00 ff ff ff ff 06 00 00 00 69 64 2e 73 79 73 00 00 ff ff ff ff 5c 00 00 00 44 38 37 35 39 31 38 36 39 36 44 46 31 32 32 46 33 38 41 36 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Banload_AQS_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQS,SIGNATURE_TYPE_PEHSTR,01 01 01 01 07 00 00 "
		
	strings :
		$a_01_0 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00 } //200
		$a_01_1 = {00 68 74 74 70 3a 2f 2f 31 36 38 2e 36 31 2e 38 37 2e 31 37 39 2f } //50 栀瑴㩰⼯㘱⸸ㄶ㠮⸷㜱⼹
		$a_01_2 = {41 70 70 6c 65 74 4d 6f 64 75 6c 65 41 63 74 69 76 61 74 65 09 54 4f 76 6f 66 72 69 74 6f } //50 灁汰瑥潍畤敬捁楴慶整吉癏景楲潴
		$a_01_3 = {54 6f 72 61 54 6f 72 61 00 } //5
		$a_01_4 = {00 53 68 65 6c 6c 33 32 2e 44 4c 4c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 00 ff ff ff } //1
		$a_01_5 = {ff ff ff ff 04 00 00 00 32 30 30 30 00 00 00 00 ff ff ff ff 02 00 00 00 58 50 00 00 ff ff ff ff 05 00 00 00 56 69 73 74 61 00 00 00 ff ff ff ff } //1
		$a_01_6 = {ff ff ff ff 07 00 00 00 75 61 63 2e 6c 6f 67 00 ff ff ff ff 04 00 00 00 5a 45 52 4f 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*200+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=257
 
}