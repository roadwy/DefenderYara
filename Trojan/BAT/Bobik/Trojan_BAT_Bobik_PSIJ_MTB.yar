
rule Trojan_BAT_Bobik_PSIJ_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PSIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 1d 28 43 00 00 0a 0b 28 90 01 03 0a 0c 07 72 21 00 00 70 08 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 16 fe 01 0d 09 2c 19 08 07 72 21 00 00 70 08 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 00 00 00 06 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}