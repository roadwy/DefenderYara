
rule Trojan_BAT_Quasar_NQS_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 07 11 06 9a 1f 10 28 90 01 01 00 00 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 3a d9 ff ff ff 90 00 } //5
		$a_01_1 = {62 41 5a 6d 54 } //1 bAZmT
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}