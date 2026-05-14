
rule Trojan_BAT_Formbook_AFN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 8d ?? ?? ?? 01 0c 16 0a 2b 12 08 06 07 06 9a 1f 10 28 ?? ?? ?? 0a d2 9c 06 17 58 0a 06 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_AFN_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 19 08 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 86 6f ?? ?? ?? 0a 00 11 07 17 d6 13 07 11 07 11 06 31 e1 } //2
		$a_01_1 = {49 00 53 00 41 00 54 00 } //1 ISAT
		$a_01_2 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d 00 } //1 QuanLyBanGiay.CCM
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}