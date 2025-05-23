
rule TrojanDownloader_Win32_Agent_SN{
	meta:
		description = "TrojanDownloader:Win32/Agent.SN,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 66 65 6a 69 2e 6c 6f 67 } //10 c:\feji.log
		$a_03_1 = {5c 70 69 70 69 5f 64 61 65 5f 90 04 03 0a 30 31 32 33 34 35 36 37 38 39 2e 65 78 65 } //1
		$a_03_2 = {5c 48 61 70 70 79 90 04 02 0a 30 31 32 33 34 35 36 37 38 39 68 79 74 2e 65 78 65 } //1
		$a_03_3 = {20 2f 76 65 72 79 73 69 6c 65 6e 74 [0-04] 5c 70 69 70 69 5f 73 65 74 75 70 25 73 25 73 25 73 25 73 5f 63 6c 65 61 6e 5f 90 04 03 0a 30 31 32 33 34 35 36 37 38 39 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}