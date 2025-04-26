
rule Trojan_BAT_Cryptbot_ACO_MTB{
	meta:
		description = "Trojan:BAT/Cryptbot.ACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 2a 08 09 06 09 91 09 1f 3b 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f ?? 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d 09 06 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}