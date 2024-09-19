
rule Trojan_Win32_LummaC_ASGK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e3 04 03 9d ?? ?? ff ff 33 d9 81 3d ?? ?? ?? 00 03 0b 00 00 75 13 6a 00 ff 15 ?? ?? ?? 00 33 c0 50 50 50 ff 15 ?? ?? ?? 00 8b 45 6c 33 c3 2b f0 } //4
		$a_03_1 = {2b f8 83 3d ?? ?? ?? 00 0c 89 45 6c 75 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}