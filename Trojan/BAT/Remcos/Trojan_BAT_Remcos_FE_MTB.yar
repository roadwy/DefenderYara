
rule Trojan_BAT_Remcos_FE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {56 61 5a 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 41 } //1 VaZzzzzzzzzzzA
		$a_81_1 = {52 75 6e 6e 6e 6e 6e } //1 Runnnnn
		$a_81_2 = {31 32 33 63 75 74 65 } //1 123cute
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_6 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_7 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}