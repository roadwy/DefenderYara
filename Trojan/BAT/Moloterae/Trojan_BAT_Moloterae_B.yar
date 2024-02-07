
rule Trojan_BAT_Moloterae_B{
	meta:
		description = "Trojan:BAT/Moloterae.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 61 69 6e 20 4e 61 74 74 6c 79 20 4e 6f 76 69 5c } //01 00  Main Nattly Novi\
		$a_01_1 = {53 68 65 6c 6c 4c 69 6e 6b 4f 62 6a 65 63 74 00 49 53 68 65 6c 6c 4c 69 6e 6b 44 75 61 6c 32 00 73 65 74 5f 41 72 67 75 6d 65 6e 74 73 } //01 00 
		$a_01_2 = {45 78 74 52 65 73 65 74 2e 65 78 65 00 46 6f 72 6d 31 } //00 00  硅剴獥瑥攮數䘀牯ㅭ
	condition:
		any of ($a_*)
 
}