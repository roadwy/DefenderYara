
rule Trojan_Win64_BumbleBee_GLA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.GLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 8b 45 e8 89 d1 31 c1 8b 55 fc 48 8b 45 f0 48 01 d0 89 ca 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}