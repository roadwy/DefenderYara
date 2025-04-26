
rule Trojan_BAT_Quasar_NVV_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 0a } //5
		$a_01_1 = {55 00 47 00 6d 00 62 00 47 00 45 00 4e 00 } //1 UGmbGEN
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}