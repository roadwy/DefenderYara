
rule Trojan_BAT_Agenttesla_ARAN_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.ARAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 13 04 09 17 58 09 20 00 9a 01 00 5d 13 05 20 00 9a 01 00 5d 13 06 07 11 05 91 13 07 1f 16 8d ?? ?? ?? 01 25 d0 ?? 00 00 04 28 ?? ?? ?? 0a 09 1f 16 5d 91 13 08 07 11 06 91 11 04 58 13 09 11 07 11 08 61 11 09 59 13 0a 07 11 05 11 0a 11 04 5d d2 9c 09 17 58 0d 09 20 00 9a 01 00 32 9d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}