
rule Trojan_WinNT_Adwind_YF_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.YF!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 41 42 50 45 43 57 41 58 43 4a 42 } //1 UABPECWAXCJB
		$a_00_1 = {4e 5a 59 4b 5e } //1 NZYK^
		$a_00_2 = {51 42 57 51 47 55 56 43 5c 50 48 54 5d 42 5a 57 52 54 44 55 56 56 55 57 } //1 QBWQGUVC\PHT]BZWRTDUVVUW
		$a_00_3 = {58 4c 5a 43 58 40 59 42 4a 56 4e 4a 58 58 5a } //1 XLZCX@YBJVNJXXZ
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}