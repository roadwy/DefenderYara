
rule Trojan_BAT_Taskun_AAEA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AAEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 22 00 06 11 04 18 6f 90 01 01 00 00 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 90 01 01 00 00 0a 9c 00 11 04 18 58 13 04 11 04 06 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d ce 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}