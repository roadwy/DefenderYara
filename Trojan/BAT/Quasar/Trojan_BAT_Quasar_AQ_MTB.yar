
rule Trojan_BAT_Quasar_AQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e b7 0b 16 02 8e b7 17 da 0d 0c 2b 10 02 08 02 08 91 03 08 07 5d 91 61 9c 08 17 d6 0c 08 09 31 ec 02 0a 2b 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Quasar_AQ_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 1b 00 06 02 07 1e 6f 22 00 00 0a 18 28 23 00 00 0a 6f 24 00 00 0a 00 00 07 1e 58 0b 07 02 6f 25 00 00 0a fe 04 0c 08 2d d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Quasar_AQ_MTB_3{
	meta:
		description = "Trojan:BAT/Quasar.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 20 00 30 00 00 1f 40 28 90 01 01 00 00 06 80 04 00 00 04 02 16 7e 90 01 01 00 00 04 02 8e 69 28 90 01 01 00 00 0a 7e 90 01 01 00 00 04 d0 05 00 00 02 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}