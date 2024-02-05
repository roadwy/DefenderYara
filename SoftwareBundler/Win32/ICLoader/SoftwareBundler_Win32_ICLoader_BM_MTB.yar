
rule SoftwareBundler_Win32_ICLoader_BM_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {03 c3 6a 00 6a 00 03 c7 6a 00 6a 00 8a 10 6a 00 6a 00 6a 00 32 d1 6a 00 6a 00 88 10 ff 90 01 01 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 43 ff 90 01 01 81 fb da 04 00 00 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}