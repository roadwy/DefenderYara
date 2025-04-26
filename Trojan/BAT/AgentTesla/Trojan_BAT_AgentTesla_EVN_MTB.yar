
rule Trojan_BAT_AgentTesla_EVN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0e 04 0b 07 17 2e 06 07 18 2e 0a 2b 2d 02 03 5d 0c 08 0a 2b 25 } //1
		$a_01_1 = {41 00 53 00 41 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 41 00 53 00 41 00 } //1 ASAMethod0ASA
		$a_01_2 = {4b 00 6b 00 4b 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 4b 00 6b 00 4b 00 } //1 KkKMethod0KkK
		$a_01_3 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 } //1 GetMethods
		$a_01_4 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 } //1 GetTypes
		$a_01_5 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EVN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 00 24 00 4d 00 4c 00 4b 00 6a 00 63 00 6c 00 6b 00 64 00 73 00 6a 00 66 00 6b 00 6c 00 73 00 64 00 66 00 6b 00 67 00 68 00 66 00 64 00 6b 00 68 00 67 00 66 00 68 00 6d 00 6a 00 6c 00 79 00 69 00 6c 00 24 00 24 00 } //1 $$MLKjclkdsjfklsdfkghfdkhgfhmjlyil$$
		$a_01_1 = {41 00 53 00 41 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 41 00 53 00 41 00 } //1 ASAMethod0ASA
		$a_01_2 = {4b 00 6b 00 4b 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 4b 00 6b 00 4b 00 } //1 KkKMethod0KkK
		$a_01_3 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 } //1 GetMethods
		$a_01_4 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 73 00 } //1 GetTypes
		$a_01_5 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}