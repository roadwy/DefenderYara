
rule Trojan_BAT_AgentTesla_ERB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 00 44 00 37 00 45 00 37 00 38 00 44 00 4f 00 36 00 50 00 59 00 38 00 48 00 37 00 53 00 58 00 5a 00 52 00 35 00 38 00 53 00 5a 00 } //10 UD7E78DO6PY8H7SXZR58SZ
		$a_01_1 = {54 00 30 00 4f 00 76 00 47 00 47 00 36 00 6b 00 75 00 6b 00 69 00 77 00 47 00 75 00 4f 00 43 00 70 00 58 00 } //5 T0OvGG6kukiwGuOCpX
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}