
rule Trojan_Win32_Smokeloader_GJA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 51 52 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 ed ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}