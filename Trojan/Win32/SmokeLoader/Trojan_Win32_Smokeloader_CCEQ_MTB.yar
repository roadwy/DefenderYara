
rule Trojan_Win32_Smokeloader_CCEQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 55 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b ?? 24 ?? 89 6c 24 ?? 8b 44 24 ?? 01 44 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}