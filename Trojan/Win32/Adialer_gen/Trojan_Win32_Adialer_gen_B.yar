
rule Trojan_Win32_Adialer_gen_B{
	meta:
		description = "Trojan:Win32/Adialer_gen.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 11 00 0c 00 00 05 00 "
		
	strings :
		$a_02_0 = {7b 61 64 75 6c 74 90 01 03 2d 90 01 04 2d 90 01 04 2d 31 31 31 31 2d 31 31 31 31 31 31 31 31 31 31 31 31 7d 90 00 } //05 00 
		$a_00_1 = {67 6f 69 63 66 62 6f 6f 67 69 64 69 6b 6b 65 6a 63 63 6d 63 6c 70 69 65 69 63 69 68 68 6c 70 6f 20 67 6a 62 6b 64 6f } //02 00  goicfboogidikkejccmclpieicihhlpo gjbkdo
		$a_00_2 = {22 25 73 22 20 50 49 44 3a 25 64 20 45 58 45 3a 22 25 73 22 } //02 00  "%s" PID:%d EXE:"%s"
		$a_00_3 = {45 78 65 44 65 6c 65 74 65 45 76 65 6e 74 } //02 00  ExeDeleteEvent
		$a_00_4 = {4d 79 57 69 6e 50 6f 70 } //02 00  MyWinPop
		$a_00_5 = {5f 64 6d 6d 5f 2e 65 78 65 } //02 00  _dmm_.exe
		$a_00_6 = {5f 66 6f 6f 62 61 72 5f 2e 65 78 65 } //01 00  _foobar_.exe
		$a_00_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  http://www.google.com
		$a_00_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 54 72 75 73 74 5c 54 72 75 73 74 20 50 72 6f 76 69 64 65 72 73 5c 53 6f 66 74 77 61 72 65 20 50 75 62 6c 69 73 68 69 6e 67 5c 54 72 75 73 74 20 44 61 74 61 62 61 73 65 5c 30 } //01 00  Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\Trust Database\0
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 } //01 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3
		$a_00_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 41 63 74 69 76 65 58 20 43 61 63 68 65 } //01 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings\ActiveX Cache
		$a_00_11 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //00 00  RegisterServiceProcess
	condition:
		any of ($a_*)
 
}