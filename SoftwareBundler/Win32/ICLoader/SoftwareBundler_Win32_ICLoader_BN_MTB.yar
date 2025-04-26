
rule SoftwareBundler_Win32_ICLoader_BN_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 14 8a 11 88 15 ?? ?? ?? ?? 8b 45 14 83 c0 01 89 45 14 8b 4d 0c 89 4d f8 ba ?? ?? ?? ?? 03 55 08 8b 45 0c 03 45 08 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 14 32 88 14 08 8b 45 08 0f be 88 ?? ?? ?? ?? 85 c9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}