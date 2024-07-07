
rule Trojan_Win64_Bumblebee_IPL_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.IPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c8 48 8b 05 90 01 04 89 0d 90 01 04 45 31 04 01 49 83 c1 04 8b 0d 90 01 04 44 8b 05 90 01 04 8b 05 90 01 04 2b 05 90 01 04 44 03 05 90 01 04 05 90 01 04 8b 15 90 00 } //1
		$a_03_1 = {0f af c1 8b 0d 90 01 04 33 ca 89 05 90 01 04 8b 05 6e 5d 05 00 05 90 01 04 03 c8 b8 90 01 04 2b 05 90 01 04 01 05 90 01 04 89 0d 90 01 04 49 81 f9 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}