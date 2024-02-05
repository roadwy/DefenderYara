
rule SoftwareBundler_Win32_ICLoader_BP_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 d1 8d 34 01 8b 4d 0c 8a 14 02 88 14 0e 8a 90 01 05 84 d2 75 90 01 01 8b 15 90 01 04 03 d0 03 ca 8a 15 90 01 04 30 11 83 3d 90 01 04 03 7e 90 00 } //01 00 
		$a_02_1 = {03 d9 03 c8 46 8a 1c 03 88 1c 39 8a 88 90 01 04 84 c9 75 90 01 01 8b 0d 90 01 04 8a 1d 90 01 04 03 c8 03 cf 30 19 39 15 90 01 04 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}