
rule Trojan_BAT_RedLine_MP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 c3 00 00 06 03 28 c2 00 00 06 28 c3 00 00 06 0a de 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_RedLine_MP_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {37 38 66 63 32 31 33 39 2d 33 63 32 63 2d 34 35 32 37 2d 38 63 34 36 2d 62 31 62 39 34 63 61 30 61 35 38 61 } //1 78fc2139-3c2c-4527-8c46-b1b94ca0a58a
		$a_01_1 = {53 68 69 74 7a } //1 Shitz
		$a_01_2 = {4b 6c 61 73 73 65 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Klassen.Properties.Resources
		$a_01_3 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}