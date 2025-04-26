
rule Trojan_Win32_Smokeloader_ZKZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 83 c0 46 89 44 24 ?? 83 6c 24 14 0a ?? 83 6c 24 ?? 3c 8a 44 24 ?? 30 04 1f 47 3b fd 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}