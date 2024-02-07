
rule Backdoor_Win32_Dapsol{
	meta:
		description = "Backdoor:Win32/Dapsol,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {4d 61 69 6e 00 63 6f 6e 63 00 90 02 04 2d 70 61 72 74 6e 65 72 90 02 04 2d 90 01 02 40 63 6f 6e 63 65 61 6c 61 72 65 61 90 00 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 6d 65 6d 62 65 72 73 2e 63 6f 6e 63 65 61 6c 61 72 65 61 2e 63 6f 6d 2f } //01 00  http://members.concealarea.com/
		$a_01_2 = {48 6f 73 74 3a 20 63 6f 6e 63 65 61 6c 61 72 65 61 2e 63 6f 6d } //01 00  Host: concealarea.com
		$a_01_3 = {50 48 4f 4e 45 4e 55 4d 42 45 52 } //01 00  PHONENUMBER
		$a_01_4 = {4d 42 45 52 53 4d 45 4d 42 45 52 53 4d 45 4d 42 45 52 53 } //01 00  MBERSMEMBERSMEMBERS
		$a_00_5 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //01 00  RasGetEntryDialParamsA
		$a_01_6 = {44 49 41 4c 5f 45 52 } //01 00  DIAL_ER
		$a_00_7 = {6d 6f 64 65 6d } //00 00  modem
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Dapsol_2{
	meta:
		description = "Backdoor:Win32/Dapsol,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 02 00 "
		
	strings :
		$a_03_0 = {4d 61 69 6e 00 63 6f 6e 63 00 90 02 04 2d 70 61 72 74 6e 65 72 90 02 04 2d 90 01 02 40 64 61 70 73 6f 6c 90 00 } //02 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 68 65 68 75 6e 2e 63 6f 6d 2f } //02 00  http://www.thehun.com/
		$a_01_2 = {68 74 74 70 3a 2f 2f 6d 61 64 74 68 75 6d 62 73 2e 63 6f 6d 2f 61 72 63 68 69 76 65 2f } //02 00  http://madthumbs.com/archive/
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 75 73 74 6c 65 72 2d 65 78 63 6c 75 73 69 76 65 2e 63 6f 6d 2f } //02 00  http://www.hustler-exclusive.com/
		$a_01_4 = {68 74 74 70 3a 2f 2f 67 61 6c 6c 65 72 69 65 73 2e 70 61 79 73 65 72 76 65 2e 63 6f 6d 2f 31 2f 33 31 39 35 32 2f 31 } //02 00  http://galleries.payserve.com/1/31952/1
		$a_00_5 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //02 00  RasGetEntryDialParamsA
		$a_01_6 = {44 49 41 4c 5f 45 52 } //02 00  DIAL_ER
		$a_00_7 = {6d 6f 64 65 6d } //01 00  modem
		$a_01_8 = {50 48 4f 4e 45 4e 55 4d 42 45 52 } //01 00  PHONENUMBER
		$a_01_9 = {4d 42 45 52 53 4d 45 4d 42 45 52 53 4d 45 4d 42 45 52 53 } //00 00  MBERSMEMBERSMEMBERS
	condition:
		any of ($a_*)
 
}