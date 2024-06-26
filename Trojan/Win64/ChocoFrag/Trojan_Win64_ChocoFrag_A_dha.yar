
rule Trojan_Win64_ChocoFrag_A_dha{
	meta:
		description = "Trojan:Win64/ChocoFrag.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 10 00 00 0a 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 66 c7 90 02 03 48 b8 90 00 } //0a 00 
		$a_03_1 = {48 81 fa 00 10 00 00 72 15 48 83 c2 27 90 01 07 48 83 c0 f8 48 83 f8 1f 90 00 } //01 00 
		$a_01_2 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_01_3 = {6f 70 65 6e 20 66 61 69 6c } //01 00  open fail
		$a_01_4 = {69 6e 73 74 61 6c 6c 20 6f 6b 20 2d 3e 20 25 64 } //01 00  install ok -> %d
		$a_01_5 = {70 72 6f 63 20 66 61 69 6c } //01 00  proc fail
		$a_01_6 = {72 65 61 64 20 63 6f 6e 66 69 67 20 66 61 69 6c } //01 00  read config fail
		$a_01_7 = {72 65 61 64 20 63 6f 6e 66 69 67 20 6f 6b } //01 00  read config ok
		$a_01_8 = {6f 70 65 6e 20 66 6c 61 73 68 20 66 61 69 6c } //01 00  open flash fail
		$a_01_9 = {6f 70 65 6e 20 66 6c 61 73 68 20 6f 6b } //01 00  open flash ok
		$a_01_10 = {69 64 20 25 64 } //01 00  id %d
		$a_01_11 = {6d 61 69 6e 2e 64 6c 6c } //01 00  main.dll
		$a_01_12 = {66 6c 61 73 68 2e 64 61 74 } //02 00  flash.dat
		$a_00_13 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 64 65 66 72 61 67 73 76 63 2e 64 6c 6c } //02 00  C:\windows\system32\defragsvc.dll
		$a_00_14 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 77 62 65 6d 5c 57 4d 49 73 76 63 2e 64 6c 6c } //02 00  C:\WINDOWS\SYSTEM32\wbem\WMIsvc.dll
		$a_00_15 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 53 44 52 53 56 43 2e 64 6c 6c } //00 00  C:\Windows\system32\SDRSVC.dll
	condition:
		any of ($a_*)
 
}