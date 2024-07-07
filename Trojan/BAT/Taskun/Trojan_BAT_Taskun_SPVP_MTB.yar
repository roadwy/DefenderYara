
rule Trojan_BAT_Taskun_SPVP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 91 61 28 90 01 03 0a 07 09 17 6a 58 08 6a 5d d4 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 09 17 6a 58 0d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}