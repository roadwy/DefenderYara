
rule Trojan_Win32_Smokeloader_SHJJ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SHJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f3 c1 e6 04 03 b5 ?? ?? ?? ?? 03 c3 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75 0c } //5
		$a_01_1 = {03 d7 33 c2 33 c1 2b d8 8b c3 c1 e8 05 c7 05 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}