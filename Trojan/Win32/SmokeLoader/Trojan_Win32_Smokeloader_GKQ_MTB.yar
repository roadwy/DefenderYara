
rule Trojan_Win32_Smokeloader_GKQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 03 45 ?? 03 f3 33 c6 33 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 29 45 ?? 81 3d ?? ?? ?? ?? 93 00 00 00 74 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 8b 45 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}