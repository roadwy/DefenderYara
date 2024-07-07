
rule Trojan_BAT_Quasar_DA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 0a 06 08 17 58 06 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d b4 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}