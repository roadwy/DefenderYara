
rule Trojan_BAT_FormBook_AAFM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 6e 02 07 17 58 } //2
		$a_01_1 = {4f 00 49 00 59 00 35 00 34 00 59 00 35 00 35 00 5a 00 42 00 45 00 51 00 34 00 34 00 47 00 46 00 34 00 46 00 35 00 37 00 4e 00 35 00 } //1 OIY54Y55ZBEQ44GF4F57N5
		$a_01_2 = {4c 00 75 00 69 00 73 00 31 00 } //1 Luis1
		$a_01_3 = {4b 6f 6c 61 69 74 6f } //1 Kolaito
		$a_01_4 = {57 00 61 00 72 00 61 00 55 00 69 00 } //1 WaraUi
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}