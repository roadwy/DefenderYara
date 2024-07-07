
rule Trojan_BAT_AgentTesla_CJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 03 07 91 09 61 d2 9c 07 17 58 0b 07 03 8e 69 3f } //10
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_CJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 1a 58 11 04 16 08 28 4a 90 01 03 28 47 90 01 03 11 04 16 11 04 8e 69 6f 8a 90 01 03 13 05 7e 19 90 01 03 11 05 6f 8b 90 01 03 7e 1f 90 01 03 02 6f 8c 90 01 03 7e 19 90 01 03 6f 8d 90 01 03 17 59 28 8e 90 01 03 16 7e 1d 90 01 03 02 1a 28 4a 90 01 03 11 05 90 00 } //10
		$a_81_1 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } //2 Debugger Detected
		$a_81_2 = {66 69 6c 65 3a 2f 2f 2f } //2 file:///
		$a_81_3 = {4c 6f 63 61 74 69 6f 6e } //2 Location
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=16
 
}