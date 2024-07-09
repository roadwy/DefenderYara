
rule Trojan_Win32_Smokeloader_GHA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 44 24 ?? 33 44 24 ?? 33 c8 51 8b c6 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? 47 86 c8 61 83 6c 24 ?? ?? 8b f0 89 74 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}