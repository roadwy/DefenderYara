
rule Trojan_WinNT_AdwindAC_YA_MTB{
	meta:
		description = "Trojan:WinNT/AdwindAC.YA!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 74 76 62 63 74 65 } //1 gtvbcte
		$a_01_1 = {63 62 65 71 67 71 62 67 6e 70 6d 63 } //1 cbeqgqbgnpmc
		$a_01_2 = {69 69 7a 6b 79 } //1 iizky
		$a_01_3 = {6e 7d 7f 6b 6a 7d 4e 4a 54 4a 42 6b 65 2a } //1 絮歿絪䩎䩔歂⩥
		$a_01_4 = {7d 69 69 5c 4a } //1 }ii\J
		$a_01_5 = {53 65 63 72 65 74 4b 65 79 53 70 65 63 } //1 SecretKeySpec
		$a_01_6 = {4f 4b 5e 4a 4b } //1 OK^JK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}