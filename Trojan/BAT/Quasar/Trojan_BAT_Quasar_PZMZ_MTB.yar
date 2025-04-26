
rule Trojan_BAT_Quasar_PZMZ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.PZMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 1e 8d 10 00 00 01 0c 07 28 10 00 00 0a 03 6f 11 00 00 0a 6f 12 00 00 0a 0d 09 16 08 16 1e 28 13 00 00 0a 06 08 6f 14 00 00 0a 06 18 6f 15 00 00 0a 06 18 6f 16 00 00 0a 06 6f 17 00 00 0a 13 04 02 28 18 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f 19 00 00 0a 13 06 28 10 00 00 0a 11 06 6f 1a 00 00 0a 13 07 dd 3a 00 00 00 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}