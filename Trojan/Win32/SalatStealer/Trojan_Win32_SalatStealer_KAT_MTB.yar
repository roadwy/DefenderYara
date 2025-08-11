
rule Trojan_Win32_SalatStealer_KAT_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 44 61 74 61 } //1 main.decryptData
		$a_81_1 = {66 69 6e 64 4c 73 61 73 73 50 72 6f 63 65 73 73 } //1 findLsassProcess
		$a_81_2 = {73 68 65 6c 6c 43 6f 6d 6d 61 6e 64 } //1 shellCommand
		$a_81_3 = {73 65 6e 64 53 63 72 65 65 6e } //1 sendScreen
		$a_81_4 = {72 75 6e 4b 65 79 6c 6f 67 67 65 72 } //1 runKeylogger
		$a_81_5 = {73 61 6c 61 74 2f 6d 61 69 6e } //1 salat/main
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}