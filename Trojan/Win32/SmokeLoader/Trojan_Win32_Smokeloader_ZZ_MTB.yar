
rule Trojan_Win32_Smokeloader_ZZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}