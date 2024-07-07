
rule Trojan_Win32_Zenpak_ASC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 38 4a 01 1d 90 02 04 40 31 c2 89 e8 50 90 00 } //1
		$a_03_1 = {f7 e1 c1 ea 08 69 c2 90 02 04 8b 4d 90 01 01 29 c1 89 c8 83 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}