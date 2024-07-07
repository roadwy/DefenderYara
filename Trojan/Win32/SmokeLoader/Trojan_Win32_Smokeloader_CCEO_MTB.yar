
rule Trojan_Win32_Smokeloader_CCEO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a a8 b2 27 c7 84 24 90 01 04 94 5a 88 45 c7 84 24 90 01 04 ff 33 8b 26 c7 84 24 90 01 04 4d 24 0a 2b c7 84 24 90 01 04 fe f4 15 66 c7 84 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}