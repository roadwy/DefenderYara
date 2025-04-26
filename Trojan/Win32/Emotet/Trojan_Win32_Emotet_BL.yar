
rule Trojan_Win32_Emotet_BL{
	meta:
		description = "Trojan:Win32/Emotet.BL,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 00 6e 00 69 00 71 00 75 00 65 00 61 00 6d 00 73 00 75 00 72 00 67 00 65 00 } //1 uniqueamsurge
		$a_01_1 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 49 00 6e 00 73 00 63 00 6f 00 72 00 65 00 2e 00 36 00 37 00 64 00 61 00 66 00 74 00 65 00 72 00 } //1 GoogleInscore.67dafter
		$a_01_2 = {6a 00 61 00 67 00 75 00 61 00 72 00 38 00 43 00 68 00 72 00 6f 00 6d 00 65 00 48 00 6a 00 75 00 64 00 67 00 65 00 43 00 68 00 72 00 6f 00 6d 00 65 00 } //1 jaguar8ChromeHjudgeChrome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}