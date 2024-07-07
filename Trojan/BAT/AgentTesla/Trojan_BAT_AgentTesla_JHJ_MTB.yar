
rule Trojan_BAT_AgentTesla_JHJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 6f 90 01 03 0a d4 8d 90 01 03 01 0d 08 09 16 09 8e 69 6f 90 01 03 0a 26 28 90 01 03 0a 09 6f 90 01 03 0a 72 90 01 03 70 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 0a dd 90 00 } //10
		$a_81_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}