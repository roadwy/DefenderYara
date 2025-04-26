
rule Trojan_Win32_LummaC_BK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 c1 f8 1f 89 44 24 0c 8b 54 24 08 c1 fa 1f 89 54 24 10 ?? ?? ?? ?? ?? ff 8b 44 24 08 89 04 24 8b 4c 24 10 89 4c 24 04 e8 } //5
		$a_01_1 = {8b 4c 24 20 81 f9 73 02 00 00 0f 8e 51 01 00 00 8b 54 24 24 81 fa 73 02 00 00 0f 8e 2c 01 00 00 8b 5c 24 28 81 fb 73 02 00 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}