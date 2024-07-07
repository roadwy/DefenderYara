
rule Trojan_Win32_DanaBot_AF_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 f1 0f 57 c0 8b cf 66 0f 13 05 90 02 20 c1 e1 90 01 01 03 ca 33 c8 81 3d 90 02 20 89 4c 24 90 00 } //1
		$a_02_1 = {8b 44 24 20 8b 8c 24 90 01 04 89 38 90 02 30 5f 5e 90 02 30 89 68 90 02 30 5d 5b 90 02 30 33 cc 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}