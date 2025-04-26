
rule Trojan_Win64_BumbleBee_TM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.TM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 31 04 18 48 83 c3 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}