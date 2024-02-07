
rule Trojan_Win32_TrueBot_A_MTB{
	meta:
		description = "Trojan:Win32/TrueBot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 64 61 74 5f 74 6d 70 2e 44 41 54 } //01 00  %s\dat_tmp.DAT
		$a_01_1 = {2f 43 20 73 79 73 74 65 6d 69 6e 66 6f 20 3e 3e 20 25 73 } //01 00  /C systeminfo >> %s
		$a_01_2 = {2f 43 20 6e 65 74 20 76 69 65 77 20 20 3e 3e 20 25 73 } //01 00  /C net view  >> %s
		$a_01_3 = {2f 43 20 69 70 63 6f 6e 66 69 67 20 20 3e 3e 20 25 73 } //01 00  /C ipconfig  >> %s
		$a_01_4 = {2f 43 20 77 68 6f 61 6d 69 20 20 3e 3e 20 25 73 } //01 00  /C whoami  >> %s
		$a_01_5 = {25 73 6d 6f 64 2f 69 6e 66 6f 2e 70 68 70 } //01 00  %smod/info.php
		$a_01_6 = {25 73 5c 44 65 66 65 6e 64 65 72 5f 54 45 4d 50 5f 25 30 38 78 2e 65 78 65 } //01 00  %s\Defender_TEMP_%08x.exe
		$a_01_7 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 53 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SoftWare\MicroSoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}