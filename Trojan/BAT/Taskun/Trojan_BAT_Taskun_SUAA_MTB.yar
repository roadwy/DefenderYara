
rule Trojan_BAT_Taskun_SUAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 00 37 00 48 00 38 00 41 00 38 00 37 00 35 00 35 00 34 00 42 00 38 00 38 00 38 00 51 00 4a 00 48 00 35 00 37 00 34 00 45 00 32 00 } //5 F7H8A87554B888QJH574E2
		$a_01_1 = {53 70 6c 69 74 } //1 Split
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}