
rule Trojan_BAT_RedLineStealer_MZ_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 13 7e ?? 00 00 04 02 6f 28 00 00 0a 74 ?? 00 00 01 0c de 5b 73 ?? 00 00 0a 0a 16 0b 2b 27 06 02 07 6f ?? ?? ?? 0a 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d0 7e 02 00 00 04 02 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c de } //1
		$a_81_1 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_3 = {53 6c 65 65 70 } //1 Sleep
		$a_81_4 = {50 75 73 68 51 75 65 75 65 } //1 PushQueue
		$a_81_5 = {54 65 73 74 51 75 65 75 65 } //1 TestQueue
		$a_81_6 = {43 6f 6d 70 75 74 65 51 75 65 75 65 } //1 ComputeQueue
		$a_81_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_8 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}