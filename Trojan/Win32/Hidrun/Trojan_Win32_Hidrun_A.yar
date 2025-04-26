
rule Trojan_Win32_Hidrun_A{
	meta:
		description = "Trojan:Win32/Hidrun.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b d8 f7 db eb ?? 0f be 46 01 46 50 e8 ?? ?? ?? ?? 8b d8 c1 e3 04 46 46 0f be 06 50 46 } //10
		$a_00_1 = {69 65 5f 68 69 64 65 5f 72 75 6e } //5 ie_hide_run
		$a_00_2 = {44 6f 77 6e 6c 6f 61 64 65 64 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 66 6c 6f 64 65 72 73 2e 69 6e 69 } //1 Downloaded Program Files\floders.ini
		$a_00_3 = {35 35 37 62 39 30 33 38 2d 66 63 38 37 2d 34 35 33 63 2d 38 62 30 38 2d 33 32 64 38 35 66 34 36 65 61 63 34 } //1 557b9038-fc87-453c-8b08-32d85f46eac4
		$a_00_4 = {73 65 61 72 63 68 2e 64 6c 6c } //1 search.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=17
 
}