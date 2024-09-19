
rule Trojan_Win32_Smokeloader_GZN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 b0 83 c0 01 89 45 b0 83 7d b0 0d ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 0f b6 11 81 f2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 b0 88 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}