
rule SoftwareBundler_Win32_ICLoader_BS_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c3 6a 00 03 c7 6a 00 6a 00 6a 00 8a 10 6a 00 32 d1 88 10 ff d5 83 3d 90 01 04 02 76 01 43 81 fb 44 07 00 00 7e 90 00 } //1
		$a_02_1 = {03 c3 03 c7 30 08 ff d5 83 3d 90 01 04 02 76 01 43 81 fb 44 07 00 00 7e 90 00 } //1
		$a_02_2 = {50 72 6f 63 c7 05 90 01 04 65 73 73 33 c7 05 90 01 04 32 46 69 72 66 c7 05 90 01 04 73 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}