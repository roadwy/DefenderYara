
rule Trojan_Win32_FlyStudio_ASDE_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.ASDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 2e 77 6b 37 62 2e 63 6f 6d 3a 38 30 39 30 } //1 sys.wk7b.com:8090
		$a_01_1 = {33 35 39 38 31 32 33 2e 65 78 65 } //1 3598123.exe
		$a_01_2 = {77 77 77 2e 62 61 69 64 75 70 63 73 2e 63 6f 6d 2f 66 69 6c 65 } //1 www.baidupcs.com/file
		$a_01_3 = {7b 45 42 35 41 38 36 37 39 2d 36 43 39 36 2d 34 34 36 35 2d 41 33 32 39 2d 37 39 31 31 34 31 38 46 32 35 38 32 7d } //1 {EB5A8679-6C96-4465-A329-7911418F2582}
		$a_01_4 = {30 44 44 33 31 36 41 42 31 30 35 34 34 32 66 38 38 32 43 34 42 35 33 35 46 34 35 45 36 33 43 42 } //1 0DD316AB105442f882C4B535F45E63CB
		$a_01_5 = {6a 73 2e 75 73 65 72 73 2e 35 31 2e 6c 61 2f 31 34 39 31 31 30 36 36 2e 6a 73 } //1 js.users.51.la/14911066.js
		$a_01_6 = {77 6b 37 62 5f 75 70 64 61 74 65 2e 65 78 65 } //1 wk7b_update.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}