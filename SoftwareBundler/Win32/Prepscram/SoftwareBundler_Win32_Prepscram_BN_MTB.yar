
rule SoftwareBundler_Win32_Prepscram_BN_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 00 88 45 ?? 8b 45 ?? 03 45 ?? 0f be 08 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 0f be 44 10 12 33 c8 8b 45 ?? 03 45 ?? 88 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}