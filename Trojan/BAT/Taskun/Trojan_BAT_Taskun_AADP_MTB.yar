
rule Trojan_BAT_Taskun_AADP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AADP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 22 00 07 11 06 18 6f 90 01 01 00 00 0a 13 07 08 11 06 18 5b 11 07 1f 10 28 90 01 01 00 00 0a 9c 00 11 06 18 58 13 06 11 06 07 6f 90 01 01 00 00 0a fe 04 13 08 11 08 2d ce 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}