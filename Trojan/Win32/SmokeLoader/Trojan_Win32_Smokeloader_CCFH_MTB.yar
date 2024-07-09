
rule Trojan_Win32_Smokeloader_CCFH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}