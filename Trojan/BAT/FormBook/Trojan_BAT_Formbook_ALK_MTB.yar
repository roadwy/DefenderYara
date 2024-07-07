
rule Trojan_BAT_Formbook_ALK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 28 00 08 09 11 04 6f 90 01 03 0a 13 0b 12 0b 28 90 01 03 0a 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 0a fe 04 13 0d 11 0d 2d c8 90 00 } //2
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 54 00 68 00 75 00 6f 00 63 00 } //1 QuanLyBanThuoc
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}