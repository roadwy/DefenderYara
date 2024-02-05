
rule SoftwareBundler_Win32_ICLoader_BQ_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 d0 03 c1 8a 0c 0a 8b 55 0c 88 0c 10 60 8d 05 90 01 04 c1 e0 05 61 8b 45 08 8a 88 90 01 04 84 c9 75 90 01 01 60 8d 05 90 01 04 c1 e0 05 61 8b 0d 90 01 04 8b 55 08 8b 45 0c 03 ca 03 c1 8a 0d 90 01 04 30 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}