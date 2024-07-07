
rule Trojan_BAT_Formbook_RPA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 cdn.discordapp.com
		$a_01_1 = {4d 00 77 00 7a 00 61 00 76 00 63 00 2e 00 6a 00 70 00 67 00 } //1 Mwzavc.jpg
		$a_01_2 = {47 00 6e 00 79 00 77 00 78 00 69 00 66 00 79 00 6e 00 64 00 61 00 73 00 72 00 71 00 6f 00 6d 00 61 00 6b 00 6c 00 69 00 } //1 Gnywxifyndasrqomakli
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_4 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_01_5 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}