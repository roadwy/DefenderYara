
rule Trojan_Win64_BumbleBee_KJ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 0a 41 ff 81 90 01 04 41 8b 49 90 01 01 41 33 89 90 01 04 2b c1 41 01 81 90 01 04 48 8b 05 90 01 04 8b 88 90 01 04 33 0d 90 01 04 41 8b 81 90 01 04 81 e9 90 01 04 41 31 49 90 01 01 05 90 01 04 09 05 90 01 04 41 8b 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}