
rule Trojan_Win32_Smokeloader_AMAQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e6 04 03 b5 ?? ?? ?? ?? 03 c3 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75 [0-14] 33 c6 2b f8 89 bd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}