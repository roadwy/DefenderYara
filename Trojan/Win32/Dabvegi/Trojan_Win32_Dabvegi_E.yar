
rule Trojan_Win32_Dabvegi_E{
	meta:
		description = "Trojan:Win32/Dabvegi.E,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 4e 65 78 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //10 FindNextUrlCacheEntryA
		$a_00_1 = {55 52 4c 53 74 61 72 74 73 57 69 74 68 } //10 URLStartsWith
		$a_02_2 = {43 55 52 4c 48 69 73 74 6f 72 69 61 [0-04] 55 52 4c 48 69 73 74 6f 72 69 61 49 74 65 6d [0-04] 52 57 4d [0-04] 43 72 54 78 74 } //10
		$a_00_3 = {2d 00 5b 00 38 00 38 00 5d 00 2d 00 } //1 -[88]-
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1) >=31
 
}