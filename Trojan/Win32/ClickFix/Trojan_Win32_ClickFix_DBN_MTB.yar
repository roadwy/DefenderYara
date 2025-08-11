
rule Trojan_Win32_ClickFix_DBN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff83 00 ffffff83 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //100 mshta
		$a_00_1 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 } //10 SHELLEXECUTE
		$a_00_2 = {44 00 65 00 6c 00 65 00 74 00 65 00 46 00 69 00 6c 00 65 00 } //10 DeleteFile
		$a_00_3 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 76 00 61 00 72 00 } //10 javascript:var
		$a_00_4 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1) >=131
 
}