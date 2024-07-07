
rule Trojan_BAT_Quasar_AALO_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AALO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 8d 90 01 01 00 00 01 0b 16 0c 2b 1b 07 08 06 08 91 20 d0 71 65 cd 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 df 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}