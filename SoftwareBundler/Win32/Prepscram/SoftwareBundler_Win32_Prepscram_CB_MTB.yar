
rule SoftwareBundler_Win32_Prepscram_CB_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c6 89 7d 90 01 01 f7 75 90 01 01 8b 45 90 01 01 8a 0c 02 8b 45 90 01 01 8a 04 06 32 c1 8b 4d 90 01 01 88 04 0e 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}