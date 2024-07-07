
rule Backdoor_Win32_PcClient_AH{
	meta:
		description = "Backdoor:Win32/PcClient.AH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 25 73 } //1 C:\Program Files\Internet Explorer\%s
		$a_01_1 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c 00 44 6f 57 6f 72 6b 45 78 00 44 6f 57 6f 72 6b 57 6c 00 } //1
		$a_03_2 = {6a 04 68 00 10 00 00 57 56 53 ff 15 90 01 04 89 45 90 01 01 3b c6 74 90 01 01 56 57 ff 75 08 50 53 ff 15 90 01 04 89 45 90 01 01 3b c6 74 90 01 01 68 90 01 04 68 90 01 04 ff 15 90 01 04 50 ff 15 90 01 04 89 45 90 01 01 3b c6 74 90 01 01 56 56 ff 75 90 01 01 50 56 56 53 ff 15 90 01 04 89 45 90 01 01 3b c6 74 90 01 01 6a ff 50 ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}