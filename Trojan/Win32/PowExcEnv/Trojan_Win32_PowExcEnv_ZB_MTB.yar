
rule Trojan_Win32_PowExcEnv_ZB_MTB{
	meta:
		description = "Trojan:Win32/PowExcEnv.ZB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 20 00 24 00 } //1 add-mppreference -exclusionpath $
		$a_00_1 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 24 00 } //1 add-mppreference -exclusionprocess $
		$a_00_2 = {66 00 6f 00 72 00 65 00 61 00 63 00 68 00 20 00 28 00 24 00 } //1 foreach ($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}