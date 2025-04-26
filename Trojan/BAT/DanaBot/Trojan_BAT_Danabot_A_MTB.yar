
rule Trojan_BAT_Danabot_A_MTB{
	meta:
		description = "Trojan:BAT/Danabot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 06 09 91 09 1f 25 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}