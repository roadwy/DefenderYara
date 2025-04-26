
rule Trojan_BAT_Taskun_AAEN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AAEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 22 00 07 11 09 18 6f ?? 00 00 0a 13 0a 08 11 09 18 5b 11 0a 1f 10 28 ?? 00 00 0a 9c 00 11 09 18 58 13 09 11 09 07 6f ?? 00 00 0a fe 04 13 0b 11 0b 2d ce } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}