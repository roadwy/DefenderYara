
rule Trojan_BAT_Dapato_AJIA_MTB{
	meta:
		description = "Trojan:BAT/Dapato.AJIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 16 1e 6f ?? 00 00 0a 0c 06 1e 6f ?? 00 00 0a 0a 08 18 28 ?? 00 00 0a 0d 07 09 d1 8c ?? 00 00 01 28 ?? 00 00 0a 0b 00 06 6f ?? 00 00 0a 16 fe 02 13 08 11 08 2d c8 07 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 13 05 11 05 } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}