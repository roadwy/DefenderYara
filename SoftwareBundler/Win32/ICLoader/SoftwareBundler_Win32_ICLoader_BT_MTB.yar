
rule SoftwareBundler_Win32_ICLoader_BT_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 46 8d 3c 10 8b 45 0c 8a 0c 11 88 0c 07 8a 8a ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 76 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}