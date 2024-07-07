
rule SoftwareBundler_Win32_Prepscram_BB_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 06 8b c6 f7 75 90 01 01 8b 45 90 01 01 88 4d 90 01 01 8a 04 02 32 c1 8b 4d 90 01 01 88 04 0e 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 89 45 90 00 } //1
		$a_02_1 = {33 d2 8b 45 90 01 01 89 75 90 01 01 8a 04 01 88 45 90 01 01 8b c1 f7 75 90 01 01 8b 45 90 01 01 8a 04 02 8b 55 90 01 01 32 45 90 01 01 88 04 11 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}