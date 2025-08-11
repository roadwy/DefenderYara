
rule Trojan_Win32_PowExcEnv_ZA_MTB{
	meta:
		description = "Trojan:Win32/PowExcEnv.ZA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 20 00 24 00 } //1 add-mppreference -exclusionpath $
		$a_00_1 = {61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 24 00 } //1 add-mppreference -exclusionprocess $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}