
rule Trojan_BAT_Spynoon_AOUA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AOUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 16 07 16 94 9e 09 17 07 17 94 9e 02 07 16 94 07 17 94 6f ?? 00 00 0a 13 06 19 8d ?? 00 00 01 13 07 11 07 16 12 06 28 ?? 00 00 0a 9c 11 07 17 12 06 28 ?? 00 00 0a 9c 11 07 18 12 06 28 ?? 00 00 0a 9c 09 18 04 03 6f ?? 00 00 0a 59 9e 09 18 94 19 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}