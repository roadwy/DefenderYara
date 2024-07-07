
rule SoftwareBundler_Win32_Prepscram_CA_MTB{
	meta:
		description = "SoftwareBundler:Win32/Prepscram.CA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 75 14 33 d2 8b 75 c4 8b c6 f7 75 e0 8b 45 08 8a 0c 02 8b 45 20 8a 04 06 32 c1 8b 4d 18 88 04 0e 8b 45 b0 89 45 b8 8b 45 cc 89 45 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}