
rule Trojan_BAT_Formbook_ASF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2a 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 91 13 09 11 04 11 09 6f ?? ?? ?? 0a 07 18 58 0b 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe 04 13 0a 11 0a 2d c2 } //2
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 56 00 65 00 4d 00 61 00 79 00 42 00 61 00 79 00 } //1 QuanLyBanVeMayBay
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}