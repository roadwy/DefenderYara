
rule Trojan_Win32_Wabot_lmnq_MTB{
	meta:
		description = "Trojan:Win32/Wabot.lmnq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 61 70 70 20 70 61 74 68 73 5c 77 69 6e 7a 69 70 33 32 2e 65 78 65 } //01 00  software\microsoft\windows\currentversion\app paths\winzip32.exe
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 61 70 70 20 70 61 74 68 73 5c 57 69 6e 52 41 52 2e 65 78 65 } //01 00  software\microsoft\windows\currentversion\app paths\WinRAR.exe
		$a_01_2 = {46 55 43 4b } //01 00  FUCK
		$a_01_3 = {73 79 73 74 65 6d 2e 69 6e 69 } //01 00  system.ini
		$a_01_4 = {43 3a 5c 72 61 72 2e 62 61 74 } //01 00  C:\rar.bat
		$a_01_5 = {43 3a 5c 7a 69 70 2e 62 61 74 } //01 00  C:\zip.bat
		$a_01_6 = {73 49 52 43 34 2e 65 78 65 } //01 00  sIRC4.exe
		$a_01_7 = {43 3a 5c 6d 61 72 69 6a 75 61 6e 61 2e 74 78 74 } //01 00  C:\marijuana.txt
		$a_01_8 = {75 6b 2e 75 6e 64 65 72 6e 65 74 2e 6f 72 67 } //01 00  uk.undernet.org
		$a_01_9 = {54 57 61 72 42 6f 74 } //00 00  TWarBot
	condition:
		any of ($a_*)
 
}