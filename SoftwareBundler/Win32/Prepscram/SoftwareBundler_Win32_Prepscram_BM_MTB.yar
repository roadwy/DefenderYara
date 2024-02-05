
rule SoftwareBundler_Win32_Prepscram_BM_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.BM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c b2 04 33 0c b2 23 cb 33 0c b2 8b c1 d1 e9 83 e0 01 69 c0 df b0 08 99 33 c1 33 84 b2 34 06 00 00 89 04 b2 46 81 fe e3 00 00 00 7c } //01 00 
		$a_01_1 = {8b 4c b2 04 33 0c b2 23 cb 33 0c b2 8b c1 d1 e9 83 e0 01 69 c0 df b0 08 99 33 c1 33 84 b2 74 fc ff ff 89 04 b2 46 81 fe 6f 02 00 00 7c } //00 00 
	condition:
		any of ($a_*)
 
}