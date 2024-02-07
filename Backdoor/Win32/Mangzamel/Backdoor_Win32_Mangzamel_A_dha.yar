
rule Backdoor_Win32_Mangzamel_A_dha{
	meta:
		description = "Backdoor:Win32/Mangzamel.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 03 00 "
		
	strings :
		$a_01_0 = {85 c0 74 3c 3d e5 03 00 00 74 35 3d 33 27 00 00 74 2e } //03 00 
		$a_03_1 = {c7 44 24 18 07 51 10 33 c7 44 24 20 00 00 00 00 e8 90 01 02 ff ff 8b 86 94 00 00 00 50 e8 90 01 02 ff ff 8b 16 83 c4 04 8b ce c7 86 94 00 00 00 00 00 00 00 68 01 51 10 33 ff 52 14 90 00 } //02 00 
		$a_00_2 = {65 77 72 3a 6d 3a 73 3a 68 3a 70 3a 74 3a 62 3a 64 3a 6e 3a 77 3a 78 3a 67 3a 6b 3a } //01 00  ewr:m:s:h:p:t:b:d:n:w:x:g:k:
		$a_00_3 = {4d 61 6e 67 2e 78 6d 6c } //01 00  Mang.xml
		$a_00_4 = {6d 61 6e 67 73 72 76 } //01 00  mangsrv
		$a_00_5 = {44 63 6f 6d 20 53 65 72 76 69 63 65 20 43 68 65 63 6b 65 72 20 53 65 72 76 69 63 65 } //01 00  Dcom Service Checker Service
		$a_00_6 = {5c 48 6f 74 66 69 78 5c 51 32 34 36 30 30 39 } //01 00  \Hotfix\Q246009
		$a_00_7 = {4c 44 53 55 70 44 76 72 } //01 00  LDSUpDvr
		$a_00_8 = {43 46 47 45 58 54 52 } //01 00  CFGEXTR
		$a_00_9 = {43 46 47 32 45 58 54 52 } //00 00  CFG2EXTR
	condition:
		any of ($a_*)
 
}