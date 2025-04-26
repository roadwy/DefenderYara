
rule Trojan_Win32_GuLoader_RPK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f ae f0 81 f5 [0-10] 55 [0-10] 59 [0-10] 89 0c 37 [0-10] 4e [0-10] 4e [0-10] 4e [0-10] 4e 7d [0-10] 89 f9 [0-10] 51 [0-10] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_GuLoader_RPK_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 2c 17 f7 c3 [0-20] 90 13 [0-20] 90 13 [0-10] 81 f5 [0-20] 90 13 [0-20] 90 13 [0-10] 01 2c 10 [0-20] 90 13 [0-20] 90 13 [0-20] 90 13 [0-10] 83 da 04 [0-20] 90 13 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}