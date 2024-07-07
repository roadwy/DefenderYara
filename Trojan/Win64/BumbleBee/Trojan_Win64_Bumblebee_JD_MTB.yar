
rule Trojan_Win64_Bumblebee_JD_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.JD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 0c 80 41 31 0c 90 01 01 8b 8b 90 01 04 81 e1 90 01 04 7d 90 01 01 2b cf 83 c9 90 01 01 03 cf 48 8b 93 90 01 04 48 63 83 90 01 04 44 8b 04 82 85 c9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Bumblebee_JD_MTB_2{
	meta:
		description = "Trojan:Win64/Bumblebee.JD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 ff 43 90 01 01 8b 83 90 01 04 83 e8 90 01 01 09 83 90 01 04 8b 43 90 01 01 2b 83 90 01 04 33 43 90 01 01 35 90 01 04 89 43 90 01 01 8b 43 90 01 01 03 c0 2b 43 90 01 01 2d 90 01 04 89 43 90 01 01 49 81 f9 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}