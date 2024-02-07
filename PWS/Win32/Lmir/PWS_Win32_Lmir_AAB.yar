
rule PWS_Win32_Lmir_AAB{
	meta:
		description = "PWS:Win32/Lmir.AAB,SIGNATURE_TYPE_PEHSTR,09 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 68 6f 6f 6b } //01 00  Ghook
		$a_01_1 = {64 65 6c 20 22 } //01 00  del "
		$a_01_2 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_01_3 = {67 6f 74 6f 20 74 72 79 } //01 00  goto try
		$a_01_4 = {64 65 6c 20 25 30 } //01 00  del %0
		$a_01_5 = {44 41 54 45 49 4e 46 4f 65 78 65 } //01 00  DATEINFOexe
		$a_01_6 = {75 72 6c 73 65 6e 64 } //01 00  urlsend
		$a_01_7 = {7e 68 6f 6f 6b } //01 00  ~hook
		$a_01_8 = {53 74 61 72 48 6f 6f 6b } //00 00  StarHook
	condition:
		any of ($a_*)
 
}