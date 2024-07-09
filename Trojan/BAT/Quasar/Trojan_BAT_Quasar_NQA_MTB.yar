
rule Trojan_BAT_Quasar_NQA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 28 fd 00 00 0a 03 04 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f ?? 01 00 0a 2a } //5
		$a_03_1 = {02 7b 45 00 00 04 02 02 7b ?? 00 00 04 03 28 ?? 00 00 06 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 17 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_BAT_Quasar_NQA_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 11 04 17 11 04 8e 69 17 59 6f ?? 00 00 0a 0b 07 13 07 07 16 6f ?? 00 00 0a 1f 20 2e 0f 07 17 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 2b 07 07 6f ?? 00 00 0a 0b 07 28 ?? 00 00 06 0b 02 8e 69 16 31 1c 72 ?? 00 00 70 } //5
		$a_01_1 = {63 32 76 61 68 63 66 69 } //1 c2vahcfi
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}