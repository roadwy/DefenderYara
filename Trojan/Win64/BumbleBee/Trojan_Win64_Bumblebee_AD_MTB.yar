
rule Trojan_Win64_BumbleBee_AD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8b 81 d0 04 00 00 49 8b 89 90 03 00 00 48 05 d9 05 00 00 48 09 81 20 01 00 00 03 d6 49 8b 81 c0 01 00 00 8b 48 50 48 81 f1 cb 11 00 00 48 63 c2 48 3b c1 72 ca } //1
		$a_01_1 = {49 8b 03 41 ff c0 48 35 c9 21 00 00 48 0b d0 49 63 c0 49 89 91 c8 01 00 00 41 8b 8a e0 00 00 00 41 2b ce 48 3b c1 76 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}