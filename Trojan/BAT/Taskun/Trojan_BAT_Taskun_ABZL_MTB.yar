
rule Trojan_BAT_Taskun_ABZL_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ABZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 28 07 09 5d 13 08 07 09 5b 13 09 08 11 08 11 09 6f 90 01 01 00 00 0a 13 0d 11 04 12 0d 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 17 58 0b 07 09 11 06 5a fe 04 13 0a 11 0a 2d cb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}