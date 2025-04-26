
rule Trojan_BAT_Nanobot_SPZM_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.SPZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 13 11 1d 11 09 91 13 20 11 1d 11 09 11 28 11 20 61 11 1b 19 58 61 11 31 61 d2 9c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}