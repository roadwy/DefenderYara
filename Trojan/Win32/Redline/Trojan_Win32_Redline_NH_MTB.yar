
rule Trojan_Win32_Redline_NH_MTB{
	meta:
		description = "Trojan:Win32/Redline.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 54 24 18 8b 44 24 4c 01 44 24 18 8b 44 24 10 33 44 24 1c 89 74 24 34 89 44 24 10 89 44 24 54 8b 44 24 54 89 44 24 34 8b 44 24 18 31 44 24 34 8b 44 24 34 89 44 24 10 89 35 90 01 04 8b 44 24 10 29 44 24 14 81 44 24 90 01 01 47 86 c8 61 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}