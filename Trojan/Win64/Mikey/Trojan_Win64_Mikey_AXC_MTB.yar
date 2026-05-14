
rule Trojan_Win64_Mikey_AXC_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 04 20 30 0c 03 48 ff c0 48 83 f8 40 72 ef eb 3a } //5
		$a_01_1 = {0f b6 44 0c 20 30 04 0b 48 ff c1 48 3b cf 72 f0 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}