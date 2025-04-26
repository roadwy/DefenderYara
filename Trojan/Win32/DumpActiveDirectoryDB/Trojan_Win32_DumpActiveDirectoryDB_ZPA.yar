
rule Trojan_Win32_DumpActiveDirectoryDB_ZPA{
	meta:
		description = "Trojan:Win32/DumpActiveDirectoryDB.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {6e 00 74 00 64 00 73 00 75 00 74 00 69 00 6c 00 } //1 ntdsutil
		$a_00_1 = {61 00 63 00 20 00 69 00 20 00 6e 00 74 00 64 00 73 00 } //1 ac i ntds
		$a_00_2 = {22 00 69 00 66 00 6d 00 22 00 } //1 "ifm"
		$a_00_3 = {63 00 72 00 65 00 61 00 74 00 65 00 20 00 66 00 75 00 6c 00 6c 00 } //1 create full
		$a_00_4 = {20 00 71 00 20 00 71 00 } //1  q q
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}