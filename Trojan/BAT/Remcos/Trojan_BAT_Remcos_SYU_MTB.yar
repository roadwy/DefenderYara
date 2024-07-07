
rule Trojan_BAT_Remcos_SYU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SYU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 8e 69 5d 1f 1d 59 1f 1d 58 06 09 06 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 91 08 09 08 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 91 61 06 09 20 8a 10 00 00 58 20 89 10 00 00 59 06 8e 69 5d 1f 09 58 1f 0f 58 1f 18 59 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 09 17 58 0d 09 6a 06 8e 69 17 59 6a 07 17 58 6e 5a 31 93 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}