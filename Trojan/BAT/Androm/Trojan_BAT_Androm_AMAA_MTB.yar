
rule Trojan_BAT_Androm_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Androm.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? 00 00 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 11 0e 28 ?? 00 00 06 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}