
rule Trojan_BAT_Taskun_FAJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.FAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 04 2b 1f 00 08 07 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? ?? 00 0a 00 00 11 04 18 58 13 04 11 04 07 6f ?? 00 00 0a fe 04 13 05 11 05 2d d1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}