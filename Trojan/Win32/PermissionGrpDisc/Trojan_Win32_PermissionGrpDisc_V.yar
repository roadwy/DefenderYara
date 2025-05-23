
rule Trojan_Win32_PermissionGrpDisc_V{
	meta:
		description = "Trojan:Win32/PermissionGrpDisc.V,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-10] 6c 00 6f 00 63 00 61 00 6c 00 [0-02] 67 00 72 00 6f 00 75 00 70 00 } //1
		$a_02_1 = {6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 [0-10] 6c 00 6f 00 63 00 61 00 6c 00 [0-02] 67 00 72 00 6f 00 75 00 70 00 } //1
		$a_02_2 = {6e 00 65 00 74 00 20 00 [0-10] 6c 00 6f 00 63 00 61 00 6c 00 [0-02] 67 00 72 00 6f 00 75 00 70 00 } //1
		$a_02_3 = {6e 00 65 00 74 00 31 00 20 00 [0-10] 6c 00 6f 00 63 00 61 00 6c 00 [0-02] 67 00 72 00 6f 00 75 00 70 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}