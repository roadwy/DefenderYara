
rule Adware_MacOS_Ketin_H{
	meta:
		description = "Adware:MacOS/Ketin.H,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_02_0 = {02 00 80 74 08 ?? c8 48 ff c8 48 83 f8 ?? 77 f2 } //2
		$a_00_1 = {55 52 4c 46 6f 72 41 70 70 6c 69 63 61 74 69 6f 6e 54 6f 4f 70 65 6e 55 52 4c } //1 URLForApplicationToOpenURL
		$a_00_2 = {77 69 6c 6c 50 65 72 66 6f 72 6d 48 54 54 50 52 65 64 69 72 65 63 74 69 6f 6e } //1 willPerformHTTPRedirection
		$a_02_3 = {48 8d 4d c8 48 89 4c 24 28 31 c9 48 89 4c 24 10 48 89 4c 24 08 48 89 04 24 c7 44 24 20 02 00 00 00 c7 44 24 18 00 00 00 00 bf 01 00 00 00 be 04 00 00 00 31 d2 b9 01 00 00 00 4d 89 ?? 49 89 d9 e8 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*2) >=6
 
}