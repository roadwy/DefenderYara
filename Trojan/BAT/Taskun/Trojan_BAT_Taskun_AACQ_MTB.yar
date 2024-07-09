
rule Trojan_BAT_Taskun_AACQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AACQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 2c 00 09 11 05 11 07 58 11 06 11 08 58 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 08 07 11 0a 9c 07 17 58 0b 00 11 08 17 58 13 08 11 08 17 fe 04 13 0b 11 0b 2d c9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}