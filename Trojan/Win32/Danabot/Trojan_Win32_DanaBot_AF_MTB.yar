
rule Trojan_Win32_DanaBot_AF_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 f1 0f 57 c0 8b cf 66 0f 13 05 [0-20] c1 e1 ?? 03 ca 33 c8 81 3d [0-20] 89 4c 24 } //1
		$a_02_1 = {8b 44 24 20 8b 8c 24 ?? ?? ?? ?? 89 38 [0-30] 5f 5e [0-30] 89 68 [0-30] 5d 5b [0-30] 33 cc } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}