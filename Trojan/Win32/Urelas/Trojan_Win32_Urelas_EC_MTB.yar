
rule Trojan_Win32_Urelas_EC_MTB{
	meta:
		description = "Trojan:Win32/Urelas.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  DuelPoker.exe
		$a_01_1 = {4e 00 65 00 77 00 62 00 61 00 64 00 75 00 67 00 69 00 2e 00 65 00 78 00 65 00 } //01 00  Newbadugi.exe
		$a_01_2 = {32 00 31 00 38 00 2e 00 35 00 34 00 2e 00 33 00 31 00 2e 00 31 00 36 00 35 00 } //01 00  218.54.31.165
		$a_01_3 = {4d 00 79 00 43 00 6f 00 6d 00 } //01 00  MyCom
		$a_01_4 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //01 00  golfinfo.ini
		$a_01_5 = {5f 00 4d 00 59 00 44 00 45 00 42 00 55 00 47 00 3a 00 } //00 00  _MYDEBUG:
	condition:
		any of ($a_*)
 
}