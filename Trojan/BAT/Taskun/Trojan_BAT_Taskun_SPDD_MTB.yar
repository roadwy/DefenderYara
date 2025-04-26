
rule Trojan_BAT_Taskun_SPDD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 11 06 58 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}