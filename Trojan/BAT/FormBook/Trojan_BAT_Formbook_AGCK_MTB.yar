
rule Trojan_BAT_Formbook_AGCK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AGCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 06 90 00 } //2
		$a_01_1 = {4f 00 41 00 6e 00 51 00 75 00 61 00 6e 00 } //1 OAnQuan
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}