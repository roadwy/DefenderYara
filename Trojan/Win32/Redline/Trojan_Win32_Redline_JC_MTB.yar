
rule Trojan_Win32_Redline_JC_MTB{
	meta:
		description = "Trojan:Win32/Redline.JC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 e2 89 5d 90 01 01 03 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 00 } //1
		$a_03_1 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 8b 45 90 01 01 33 c1 2b f8 89 45 90 01 01 89 1d 90 01 04 89 7d 90 01 01 8b 45 90 01 01 29 45 90 01 01 83 6d d8 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}