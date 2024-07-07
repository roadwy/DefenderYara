
rule Trojan_BAT_Vidar_PTAV_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 77 00 00 70 0a 72 85 00 00 70 0b 28 90 01 01 00 00 0a 6f 11 00 00 0a 28 90 01 01 00 00 0a 0c 08 06 6f 13 00 00 0a 2c 1a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}