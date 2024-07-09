
rule SoftwareBundler_Win32_Prepscram_CB_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c6 89 7d ?? f7 75 ?? 8b 45 ?? 8a 0c 02 8b 45 ?? 8a 04 06 32 c1 8b 4d ?? 88 04 0e 8b 45 ?? 89 45 ?? 8b 45 ?? 89 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}