
rule Trojan_BAT_Sofacy_S_MTB{
	meta:
		description = "Trojan:BAT/Sofacy.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 5f 54 69 63 6b } //1 start_Tick
		$a_01_1 = {73 63 72 65 65 6e 5f 54 69 63 6b } //1 screen_Tick
		$a_01_2 = {73 75 62 6a 65 63 74 5f 54 69 63 6b } //1 subject_Tick
		$a_01_3 = {44 00 6f 00 6d 00 61 00 69 00 6e 00 3a 00 20 00 20 00 7b 00 30 00 7d 00 } //1 Domain:  {0}
		$a_01_4 = {57 00 6f 00 72 00 6b 00 69 00 6e 00 67 00 3a 00 20 00 7b 00 30 00 7d 00 } //1 Working: {0}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}