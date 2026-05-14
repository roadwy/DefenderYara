
rule Trojan_Win32_TrueChaos_DB_MTB{
	meta:
		description = "Trojan:Win32/TrueChaos.DB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_1 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 37 00 2e 00 32 00 33 00 37 00 2e 00 31 00 35 00 2e 00 31 00 39 00 37 00 } //1 ftp://47.237.15.197
		$a_00_2 = {77 00 69 00 6e 00 72 00 61 00 72 00 2e 00 65 00 78 00 65 00 20 00 78 00 } //1 winrar.exe x
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}