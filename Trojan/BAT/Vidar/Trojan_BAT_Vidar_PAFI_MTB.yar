
rule Trojan_BAT_Vidar_PAFI_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PAFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 09 06 08 06 09 91 9c 06 09 11 09 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 0a 02 11 08 8f 1d 00 00 01 25 71 1d 00 00 01 06 11 0a 91 61 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}