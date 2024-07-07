
rule Trojan_BAT_Remcos_FO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 79 21 73 74 65 6d 2e 52 65 66 6c 21 65 63 74 69 6f 6e 2e 41 73 21 73 65 6d 62 6c 79 } //1 Sy!stem.Refl!ection.As!sembly
		$a_81_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_2 = {43 6f 6e 73 6f 6c 65 41 70 70 } //1 ConsoleApp
		$a_81_3 = {42 61 73 65 36 34 53 74 72 69 6e 67 } //1 Base64String
		$a_81_4 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {41 6e 79 44 65 73 6b } //1 AnyDesk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}