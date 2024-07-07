
rule Trojan_Win32_Remcos_SD_{
	meta:
		description = "Trojan:Win32/Remcos.SD!!Remcos.gen!SD,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 66 66 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 } //1 Offline Keylogger
		$a_01_1 = {53 63 72 65 65 6e 73 68 6f 74 73 } //1 Screenshots
		$a_01_2 = {4d 69 63 52 65 63 6f 72 64 73 } //1 MicRecords
		$a_81_3 = {72 65 6d 63 6f 73 } //1 remcos
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}