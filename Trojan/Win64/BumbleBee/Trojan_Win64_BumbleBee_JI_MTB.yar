
rule Trojan_Win64_BumbleBee_JI_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.JI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 ff 05 90 01 04 48 8b 05 90 01 04 8b 88 90 01 04 33 88 90 01 04 81 e9 90 01 04 01 8b 90 01 04 48 8b 05 90 01 04 8b 88 90 01 04 81 c1 90 01 04 03 4b 90 01 01 01 8b 90 01 04 48 8b 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}