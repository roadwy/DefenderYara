
rule Trojan_BAT_Formbook_AJFM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AJFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0a 2b 50 11 0a 11 14 5d 13 16 11 0a 11 18 5d 13 1b 11 0b 11 16 91 13 1c 11 15 11 1b 6f 90 01 03 0a 13 1d 11 0b 11 0a 17 58 11 14 5d 91 13 1e 11 1c 11 1d 61 11 1e 59 20 00 01 00 00 58 13 1f 11 0b 11 16 11 1f 20 00 01 00 00 5d d2 9c 11 0a 17 59 13 0a 11 0a 16 fe 04 16 fe 01 13 20 11 20 2d a2 90 00 } //2
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 4b 00 68 00 6f 00 42 00 61 00 6e 00 68 00 4b 00 65 00 6f 00 } //1 QuanLyKhoBanhKeo
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}