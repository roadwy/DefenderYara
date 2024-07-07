
rule SoftwareBundler_Win32_ICLoader_BO_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ee 10 8a 0e bb 90 01 04 88 0d 90 01 04 8b 0d 90 01 04 03 d9 03 c8 46 8a 1c 03 88 1c 39 8a 88 90 01 04 84 c9 75 12 8b 0d 90 01 04 8a 1d 90 01 04 03 c8 03 cf 30 19 39 15 90 01 04 7e 03 40 eb 01 cf 3d 7d 05 00 00 7e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}