
rule Spammer_Win32_EmailBomb_F{
	meta:
		description = "Spammer:Win32/EmailBomb.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {36 37 41 39 30 41 46 38 2d 35 35 30 35 2d 34 63 62 39 2d 41 42 31 36 2d 37 33 45 42 41 46 37 45 46 37 38 34 } //1 67A90AF8-5505-4cb9-AB16-73EBAF7EF784
		$a_00_1 = {25 73 3f 74 79 70 65 3d 25 73 26 73 79 73 74 65 6d 3d 25 73 26 69 64 3d 25 73 26 6e 3d 25 64 26 73 74 61 74 75 73 3d 25 73 } //1 %s?type=%s&system=%s&id=%s&n=%d&status=%s
		$a_00_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 61 } //1 if exist "%s" goto a
		$a_03_3 = {b9 0d 00 00 00 be ?? ?? ?? ?? 8d bc 24 ?? ?? 00 00 f3 a5 89 44 24 1c 66 a5 ff 15 ?? ?? ?? ?? 68 94 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}