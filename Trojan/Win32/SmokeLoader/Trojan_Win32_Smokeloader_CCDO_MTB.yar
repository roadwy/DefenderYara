
rule Trojan_Win32_Smokeloader_CCDO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 2f 33 f0 8b 44 24 90 01 01 33 c6 2b d8 81 c5 90 01 04 ff 4c 24 90 01 01 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}