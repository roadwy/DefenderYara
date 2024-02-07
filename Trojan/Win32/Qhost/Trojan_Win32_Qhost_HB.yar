
rule Trojan_Win32_Qhost_HB{
	meta:
		description = "Trojan:Win32/Qhost.HB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 69 6e 67 68 75 78 2e 65 78 65 } //01 00  pinghux.exe
		$a_01_1 = {6a 75 6e 6d 69 6e 67 2e 65 78 65 } //01 00  junming.exe
		$a_01_2 = {68 65 73 68 61 6e 67 2e 65 78 65 } //01 00  heshang.exe
		$a_01_3 = {68 75 79 6f 75 70 6f 78 2e 65 78 65 } //01 00  huyoupox.exe
		$a_01_4 = {44 45 54 43 41 58 5a 2e 65 78 65 } //01 00  DETCAXZ.exe
		$a_01_5 = {72 75 79 75 68 65 38 35 31 2e 65 78 65 } //01 00  ruyuhe851.exe
		$a_01_6 = {56 6e 72 59 6e 65 31 37 33 2e 65 78 65 } //01 00  VnrYne173.exe
		$a_01_7 = {75 4d 75 65 7a 72 33 35 32 2e 65 78 65 } //01 00  uMuezr352.exe
		$a_01_8 = {58 6e 75 79 65 6e 33 32 31 2e 65 78 65 } //01 00  Xnuyen321.exe
		$a_01_9 = {54 75 78 59 77 7a 35 36 39 2e 65 78 65 } //01 00  TuxYwz569.exe
		$a_01_10 = {43 6d 77 65 75 31 75 2e 65 78 65 } //01 00  Cmweu1u.exe
		$a_01_11 = {64 66 65 33 32 55 59 44 2e 65 78 65 } //01 00  dfe32UYD.exe
		$a_01_12 = {76 4a 45 48 6a 5a 52 2e 65 78 65 } //0a 00  vJEHjZR.exe
		$a_01_13 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //0a 00  drivers\etc\hosts
		$a_01_14 = {31 32 37 2e 30 2e 30 2e 31 20 20 20 20 20 20 20 67 6d 73 2e 61 68 6e 6c 61 62 2e 63 6f 6d } //00 00  127.0.0.1       gms.ahnlab.com
		$a_00_15 = {5d 04 00 00 da ba 02 80 5c 25 00 00 db ba 02 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}