
rule Trojan_BAT_Bobik_PTCD_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PTCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 2c 00 00 0a 0b 00 07 0c 16 0d 38 e6 00 00 00 08 09 9a 13 04 00 72 a6 03 00 70 11 04 28 ?? 00 00 0a 28 ?? 00 00 06 00 11 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}