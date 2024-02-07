
rule Backdoor_Win32_Zapchast_D{
	meta:
		description = "Backdoor:Win32/Zapchast.D,SIGNATURE_TYPE_PEHSTR,2c 00 28 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 72 65 65 74 69 6e 67 20 43 61 72 64 } //0a 00  Greeting Card
		$a_01_1 = {66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 54 65 6d 70 5c 73 70 6f 6f 6c 5c 73 70 6f 6f 6c 73 76 2e 65 78 65 20 73 70 6f 6f 6c 73 76 } //01 00  firewall add allowedprogram C:\WINDOWS\Temp\spool\spoolsv.exe spoolsv
		$a_01_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 73 76 63 68 6f 73 74 5c 50 61 72 61 6d 65 74 65 72 73 } //01 00  SYSTEM\CurrentControlSet\Services\svchost\Parameters
		$a_01_3 = {40 24 26 25 30 34 5c 74 61 73 6b 62 61 72 2e 64 6c 6c } //0a 00  @$&%04\taskbar.dll
		$a_01_4 = {40 24 26 25 30 34 5c 78 6d 61 73 2e 6a 70 67 } //0a 00  @$&%04\xmas.jpg
		$a_01_5 = {40 24 26 25 30 34 5c 64 72 2e 6d 72 63 } //01 00  @$&%04\dr.mrc
		$a_01_6 = {40 24 26 25 30 34 5c 70 6f 70 75 70 73 2e 74 78 74 } //0a 00  @$&%04\popups.txt
		$a_01_7 = {2b 48 20 2b 53 20 40 24 26 25 30 32 5c 74 65 6d 70 5c 73 70 6f 6f 6c } //00 00  +H +S @$&%02\temp\spool
	condition:
		any of ($a_*)
 
}