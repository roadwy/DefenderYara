
rule SoftwareBundler_Win32_Prepscram_BB_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 06 8b c6 f7 75 ?? 8b 45 ?? 88 4d ?? 8a 04 02 32 c1 8b 4d ?? 88 04 0e 8b 45 ?? 89 45 ?? 8b 45 ?? 89 45 } //1
		$a_02_1 = {33 d2 8b 45 ?? 89 75 ?? 8a 04 01 88 45 ?? 8b c1 f7 75 ?? 8b 45 ?? 8a 04 02 8b 55 ?? 32 45 ?? 88 04 11 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}