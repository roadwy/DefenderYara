
rule SoftwareBundler_Win32_ICLoader_DSA_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 54 24 0c 53 8a 1c 08 32 da 88 1c 08 8b 0d ?? ?? ?? ?? 33 c0 5b 8a 41 01 8b 4c 24 08 0c 03 23 c1 c3 90 09 05 00 a1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}