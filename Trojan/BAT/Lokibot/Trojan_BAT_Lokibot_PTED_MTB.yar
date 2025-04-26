
rule Trojan_BAT_Lokibot_PTED_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PTED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 58 0a 2b 43 06 09 5d 13 05 06 11 08 5d 13 0c 07 11 05 91 13 0d 11 04 11 0c 6f b3 00 00 0a 13 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}