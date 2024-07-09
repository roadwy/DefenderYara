
rule Trojan_BAT_Formbook_AIW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 1f 07 11 06 11 07 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 07 17 58 13 07 11 07 07 6f ?? ?? ?? 0a 32 d7 11 06 } //2
		$a_01_1 = {4f 00 50 00 4e 00 31 00 4c 00 57 00 5f 00 76 00 31 00 2e 00 5f 00 31 00 } //1 OPN1LW_v1._1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Formbook_AIW_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 08 8e 69 5d 08 11 06 08 8e 69 5d 91 09 11 06 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 08 11 06 17 58 08 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d ac } //2
		$a_01_1 = {44 00 6f 00 41 00 6e 00 42 00 61 00 6f 00 43 00 61 00 6f 00 } //1 DoAnBaoCao
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}