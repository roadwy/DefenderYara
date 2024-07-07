
rule Trojan_BAT_Nancat_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Nancat.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 06 1f 16 5d 91 13 0c } //1
		$a_01_1 = {11 0b 11 0c 61 13 0e } //1
		$a_01_2 = {11 01 11 09 11 0f 11 07 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Nancat_MBFV_MTB_2{
	meta:
		description = "Trojan:BAT/Nancat.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 09 4c 00 6f 00 61 00 64 } //1
		$a_01_1 = {47 00 64 00 52 00 4f 00 57 00 43 00 76 00 66 00 50 00 59 00 6c 00 34 00 39 00 6a 00 65 00 4a 00 65 00 48 00 2e 00 48 00 61 00 43 00 56 00 6a 00 5a 00 33 00 68 00 69 00 37 00 74 00 49 00 34 00 75 00 6f 00 79 00 38 00 4e 00 } //1 GdROWCvfPYl49jeJeH.HaCVjZ3hi7tI4uoy8N
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}