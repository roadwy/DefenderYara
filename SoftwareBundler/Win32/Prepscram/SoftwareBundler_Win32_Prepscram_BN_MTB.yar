
rule SoftwareBundler_Win32_Prepscram_BN_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 00 88 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 0f be 08 8b 45 90 01 01 33 d2 f7 75 90 01 01 8b 45 90 01 01 0f be 44 10 12 33 c8 8b 45 90 01 01 03 45 90 01 01 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}