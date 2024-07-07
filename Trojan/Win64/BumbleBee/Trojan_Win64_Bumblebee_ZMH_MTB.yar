
rule Trojan_Win64_Bumblebee_ZMH_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.ZMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d6 09 15 90 01 04 44 31 04 03 48 83 c3 04 48 8b 05 90 01 04 44 8b 05 90 01 04 44 03 80 90 01 04 8b 05 90 01 04 33 05 90 01 04 33 05 90 01 04 35 90 01 04 44 89 05 90 01 04 89 05 90 01 04 48 81 fb 90 01 04 7c 90 01 01 90 0a 65 00 8b 15 90 01 04 03 15 90 01 04 48 8b 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}