
rule Trojan_Win32_Amadey_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e8 ?? 03 ce 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 31 4d ?? 81 3d ?? ?? ?? ?? 03 0b 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}