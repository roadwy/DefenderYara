
rule Trojan_BAT_Remcos_ASKL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 d2 13 11 11 06 11 11 20 ff 00 00 00 5f 95 d2 13 12 11 10 11 12 61 13 13 11 07 11 0f d4 11 13 20 ff 00 00 00 5f d2 9c 00 11 0f 17 6a 58 13 0f 11 0f 11 07 8e 69 17 59 6a fe 02 16 fe 01 } //4
		$a_01_1 = {35 00 32 00 34 00 4f 00 5a 00 34 00 43 00 54 00 51 00 37 00 5a 00 4a 00 38 00 47 00 45 00 37 00 49 00 37 00 43 00 38 00 4a 00 41 00 } //1 524OZ4CTQ7ZJ8GE7I7C8JA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}