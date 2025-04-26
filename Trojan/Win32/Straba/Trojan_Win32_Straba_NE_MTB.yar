
rule Trojan_Win32_Straba_NE_MTB{
	meta:
		description = "Trojan:Win32/Straba.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 62 76 79 45 78 64 76 67 } //5 IbvyExdvg
		$a_01_1 = {49 62 68 75 67 76 79 52 79 76 67 68 } //5 IbhugvyRyvgh
		$a_01_2 = {4f 69 62 68 52 74 63 66 } //5 OibhRtcf
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_4 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 41 73 46 69 6c 65 54 69 6d 65 } //1 GetSystemTimeAsFileTime
		$a_01_5 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 } //1 GetCurrentThread
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=18
 
}