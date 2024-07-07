
rule Trojan_BAT_AgentTesla_NAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 46 6f 72 53 74 72 72 69 6e 67 } //10 SForStrring
		$a_01_1 = {44 65 63 6f 64 65 72 } //10 Decoder
		$a_03_2 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 90 00 } //1
		$a_01_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp1.Properties.Resources.resources
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_5 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_7 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}