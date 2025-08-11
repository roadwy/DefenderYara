
rule Trojan_Win64_BumbleBee_GVA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 30 1e 48 81 c6 01 00 00 00 48 81 c3 83 31 30 f9 49 81 eb 01 00 00 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}