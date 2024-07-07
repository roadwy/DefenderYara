
rule Trojan_BAT_Quasar_NVV_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 72 90 01 01 00 00 70 02 73 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 06 02 6f 90 01 01 00 00 0a 0b 25 07 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 26 de 0a 90 00 } //5
		$a_01_1 = {55 00 47 00 6d 00 62 00 47 00 45 00 4e 00 } //1 UGmbGEN
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}