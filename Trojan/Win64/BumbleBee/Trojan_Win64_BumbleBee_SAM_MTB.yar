
rule Trojan_Win64_BumbleBee_SAM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 8b 0c 19 49 90 01 03 8b 48 90 01 01 2b 48 90 01 01 33 88 90 01 04 44 90 01 04 81 f1 90 01 04 89 88 90 00 } //1
		$a_03_1 = {44 88 0c 0a ff 40 90 01 01 8b 88 90 01 04 8b 50 90 01 01 83 e9 90 01 01 01 48 90 01 01 81 c2 90 01 04 03 50 90 01 01 31 90 01 05 49 81 fb 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}