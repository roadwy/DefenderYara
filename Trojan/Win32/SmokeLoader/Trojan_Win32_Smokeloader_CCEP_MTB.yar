
rule Trojan_Win32_Smokeloader_CCEP_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 } //1
		$a_03_1 = {01 45 fc 8b 7d ?? 8b 4d ?? 8d 04 3b 31 45 fc d3 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}