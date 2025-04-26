
rule Trojan_Win32_Smokeloader_ZY_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 45 e0 01 45 f8 8b 45 f8 33 45 f4 31 45 fc 8b 45 fc 29 45 e8 8b 4d d4 81 c7 ?? ?? ?? ?? 89 7d f0 4e 0f 85 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}