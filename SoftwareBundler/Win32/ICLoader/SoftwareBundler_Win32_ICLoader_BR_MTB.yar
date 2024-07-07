
rule SoftwareBundler_Win32_ICLoader_BR_MTB{
	meta:
		description = "SoftwareBundler:Win32/ICLoader.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {61 8b 55 08 83 e2 0f 85 d2 75 90 01 01 8b 45 90 01 01 83 e8 10 89 45 90 01 01 60 8b 90 01 01 83 90 01 02 83 90 01 02 8d 90 00 } //1
		$a_02_1 = {61 8b 4d 14 8a 11 88 15 90 01 04 8b 45 90 01 01 83 c0 01 89 45 90 01 01 60 8b 90 00 } //1
		$a_02_2 = {8b 4d 08 83 c1 01 89 4d 90 01 01 eb 90 01 01 ff e1 81 7d 90 01 01 04 05 00 00 7e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}