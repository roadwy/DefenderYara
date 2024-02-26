
rule Trojan_Win32_Pinchduke_A_MTB{
	meta:
		description = "Trojan:Win32/Pinchduke.A!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 75 62 64 6f 6d 2e 64 6f 6d 2e 63 6f 6d } //01 00  subdom.dom.com
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 61 69 6c 2e 52 75 5c 41 67 65 6e 74 5c 6d 72 61 5f 6c 6f 67 69 6e 73 } //01 00  Software\Mail.Ru\Agent\mra_logins
		$a_01_2 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 6d 61 72 74 46 54 50 5c 43 6c 69 65 6e 74 20 32 2e 30 5c 46 61 76 6f 72 69 74 65 73 } //01 00  %USERPROFILE%\Application Data\SmartFTP\Client 2.0\Favorites
		$a_01_3 = {6c 65 73 6b 7a 5f 32 30 31 30 30 34 31 34 } //01 00  leskz_20100414
		$a_01_4 = {70 69 70 65 5c 73 79 73 74 65 6d 66 6c 61 67 73 65 6d 61 66 6f 72 65 } //01 00  pipe\systemflagsemafore
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 61 69 6c 2e 52 75 5c 41 67 65 6e 74 5c 6d 61 67 65 6e 74 5f 6c 6f 67 69 6e 73 } //01 00  Software\Mail.Ru\Agent\magent_logins
		$a_01_6 = {22 25 54 45 4d 50 25 5c 73 6d 73 73 2e 65 78 65 22 } //00 00  "%TEMP%\smss.exe"
	condition:
		any of ($a_*)
 
}