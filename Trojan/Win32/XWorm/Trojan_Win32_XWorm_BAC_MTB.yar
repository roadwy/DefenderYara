
rule Trojan_Win32_XWorm_BAC_MTB{
	meta:
		description = "Trojan:Win32/XWorm.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 f0 8a 06 83 c6 02 88 02 8b 55 f8 0f b6 c0 05 00 01 00 00 c1 e0 08 03 c1 41 88 14 18 8b 55 f0 42 89 55 f0 81 f9 00 01 00 00 7c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}