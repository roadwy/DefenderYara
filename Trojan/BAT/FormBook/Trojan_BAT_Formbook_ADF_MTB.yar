
rule Trojan_BAT_Formbook_ADF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 34 16 13 05 2b 1f 07 11 04 11 05 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a 32 d7 11 04 17 58 13 04 11 04 07 } //2
		$a_01_1 = {4f 00 50 00 4e 00 31 00 4c 00 57 00 5f 00 76 00 31 00 2e 00 5f 00 31 00 } //1 OPN1LW_v1._1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}