
rule Trojan_BAT_AgentTesla_NRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {0d 06 6f 29 00 00 0a 09 16 09 8e 69 6f 90 01 03 0a 13 04 90 00 } //5
		$a_01_1 = {3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 32 00 34 00 36 00 2e 00 32 00 32 00 30 00 2e 00 36 00 35 00 2f 00 70 00 65 00 65 00 2f 00 49 00 6a 00 7a 00 71 00 6a 00 64 00 2e 00 6a 00 70 00 65 00 67 00 } //1 ://185.246.220.65/pee/Ijzqjd.jpeg
		$a_01_2 = {50 00 4f 00 31 00 31 00 37 00 39 00 35 00 34 00 30 00 30 00 } //1 PO11795400
		$a_01_3 = {4d 00 6e 00 77 00 65 00 6e 00 76 00 6f 00 7a 00 62 00 62 00 6f 00 69 00 68 00 } //1 Mnwenvozbboih
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_NRN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 ff b6 3f 09 0f 00 00 00 fa 00 33 00 06 00 00 01 00 00 00 cd 00 00 00 14 01 00 00 09 03 00 00 6b 03 00 00 31 02 00 00 02 00 00 00 e9 01 00 00 51 00 00 00 29 00 00 00 01 00 00 00 01 00 00 00 0b } //1
		$a_81_1 = {73 73 73 73 73 72 72 72 72 72 72 72 72 72 64 64 73 64 61 73 2e 65 78 65 } //1 sssssrrrrrrrrrddsdas.exe
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 66 00 66 00 67 00 67 00 66 00 66 00 66 00 66 00 66 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 2f 00 } //1 http://gffggfffffrograms/
		$a_81_3 = {43 3a 5c 73 6f 6d 65 64 69 72 65 63 74 6f 72 79 } //1 C:\somedirectory
		$a_81_4 = {52 65 70 6f 72 74 69 6e 67 2e 61 73 6d 78 } //1 Reporting.asmx
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}