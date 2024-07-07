
rule Trojan_Win64_Bumblebee_VIL_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 80 c1 0a ff c7 22 d1 85 c0 74 10 49 8b 4a 90 01 01 8a 04 0e 02 c0 0a c2 88 04 0e eb 07 49 8b 42 90 01 01 88 14 06 49 8b 82 90 01 04 48 31 68 90 01 01 49 8b 82 90 01 04 48 0f af 05 90 01 04 49 8b 92 08 03 00 00 49 89 82 90 01 04 49 8b 82 90 01 04 48 8b 88 90 01 04 48 81 c1 90 01 04 48 31 8a 90 01 04 49 8b 82 c8 03 00 00 48 8b 88 90 01 04 48 81 e9 90 01 04 48 63 c7 48 3b c1 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}