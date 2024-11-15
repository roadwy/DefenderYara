
rule Trojan_Win64_BumbleBee_KYI_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.KYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 41 54 48 63 4b 74 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 43 74 48 63 4b 74 48 8b 05 00 79 18 00 c1 ea 08 88 14 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}