
rule Trojan_Win64_BumbleBee_LA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b ce 83 64 24 90 01 02 49 8b e8 48 81 f5 90 01 04 41 81 c0 90 01 04 48 8b d5 90 00 } //1
		$a_03_1 = {48 8b 6c 24 90 01 01 48 8b 74 24 90 01 01 48 29 98 90 01 04 49 8b 8f 90 01 04 49 8b 87 90 01 04 48 8b 5c 24 90 01 01 48 2b c7 48 31 81 90 01 04 49 8b 87 90 01 04 49 8b 8f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}