
rule Trojan_Win64_Bumblebee_ZMY_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.ZMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 01 4b 90 01 01 8b 43 90 01 01 48 8b 8b 90 01 04 35 90 01 04 09 83 90 01 04 8b 83 90 01 04 33 83 90 01 04 35 90 01 04 89 83 90 01 04 8b 83 90 01 04 2b 43 90 01 01 2d 90 01 04 01 83 90 01 04 8b 43 90 01 01 31 04 11 48 83 c2 90 01 01 8b 83 90 01 04 01 43 90 01 01 8b 83 90 01 04 01 43 90 01 01 48 81 fa 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}