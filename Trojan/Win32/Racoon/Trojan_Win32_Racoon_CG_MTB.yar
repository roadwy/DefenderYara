
rule Trojan_Win32_Racoon_CG_MTB{
	meta:
		description = "Trojan:Win32/Racoon.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 1c 01 8b 4d 90 01 01 d3 e8 c7 05 90 01 04 2e ce 50 91 89 45 90 01 01 8b 85 90 01 04 01 45 90 01 01 8b 55 90 01 01 33 d3 33 55 90 01 01 8d 8d 90 01 04 89 55 90 01 01 e8 90 01 04 89 75 90 01 01 25 1b 07 d0 4d 81 6d 90 01 01 88 eb 73 22 bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 9d 90 01 04 8b 4d 90 01 01 8b 95 90 01 04 8b c3 d3 e0 8d 4d 90 01 01 89 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}