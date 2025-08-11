
rule Trojan_Win32_PowExcEnv_H_MTB{
	meta:
		description = "Trojan:Win32/PowExcEnv.H!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 } //1 Add-MpPreference
		$a_00_1 = {2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 } //1 -exclusion
		$a_00_2 = {24 00 65 00 6e 00 76 00 3a 00 } //1 $env:
		$a_00_3 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 } //1 appdata
		$a_00_4 = {2d 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //1 -replace
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}