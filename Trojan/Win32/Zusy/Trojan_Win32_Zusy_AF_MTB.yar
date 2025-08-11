
rule Trojan_Win32_Zusy_AF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 01 8b 51 04 89 46 04 8b 46 08 89 56 0c 8b 48 04 89 4e 10 89 d1 8b 10 8b 46 04 33 4e 10 31 d0 89 56 14 31 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}