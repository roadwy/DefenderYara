
rule Trojan_BAT_Taskun_UUAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.UUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 09 20 00 1c 01 00 28 ?? 00 00 06 00 09 6f ?? 00 00 0a 00 00 11 07 17 58 13 07 11 07 07 6f ?? 00 00 0a fe 04 13 09 11 09 2d 9e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}