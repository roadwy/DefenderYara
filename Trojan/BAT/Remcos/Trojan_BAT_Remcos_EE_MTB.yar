
rule Trojan_BAT_Remcos_EE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 6f 72 6f 6e 6f 76 69 72 75 73 2e 43 6f 72 6f 6e 6f 76 69 72 75 73 } //1 Coronovirus.Coronovirus
		$a_81_1 = {66 69 6c 65 3a 2f 2f 2f } //1 file:///
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {53 70 69 64 65 72 6d 61 6e 20 49 49 49 } //1 Spiderman III
		$a_81_4 = {4d 6f 76 69 65 52 61 74 69 6e 67 } //1 MovieRating
		$a_81_5 = {4b 65 65 70 41 6c 69 76 65 } //1 KeepAlive
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}