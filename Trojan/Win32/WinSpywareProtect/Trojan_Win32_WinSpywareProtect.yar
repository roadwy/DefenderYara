
rule Trojan_Win32_WinSpywareProtect{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 0b 00 "
		
	strings :
		$a_03_0 = {02 16 c1 c2 90 01 01 81 f2 90 01 04 46 80 3e 00 75 ef 31 fa 83 fa 00 74 1b 01 c6 81 e8 90 01 04 8b 30 01 ca 01 ce 5a 42 52 81 e2 90 01 04 31 d2 eb cd 90 00 } //0b 00 
		$a_03_1 = {02 17 47 c1 c2 90 01 01 81 f2 90 01 04 80 3f 00 75 ef 31 c2 83 fa 00 74 11 81 c6 04 00 00 00 8b 3e 01 cf 5a 42 52 31 d2 eb d7 90 00 } //0b 00 
		$a_03_2 = {02 17 c1 ca 90 01 01 81 f2 90 01 04 47 80 3f 00 75 ef 31 c2 83 fa 00 74 11 5a 42 52 81 c6 04 00 00 00 8b 3e 01 cf 31 d2 eb d7 90 00 } //09 00 
		$a_02_3 = {77 69 6e 73 70 79 77 61 72 65 70 72 6f 74 65 63 74 90 02 03 2e 63 6f 6d 90 00 } //01 00 
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_2{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 6f 66 20 53 6d 61 72 74 20 44 65 66 65 6e 64 65 72 20 50 52 4f 20 69 6e 20 70 72 6f 67 72 65 73 73 2c 20 70 6c 65 61 73 65 20 77 61 69 74 2e 2e 2e } //01 00  Installation of Smart Defender PRO in progress, please wait...
		$a_01_1 = {25 00 73 00 73 00 6d 00 72 00 74 00 64 00 65 00 66 00 70 00 2e 00 65 00 78 00 65 00 } //01 00  %ssmrtdefp.exe
		$a_01_2 = {61 00 62 00 72 00 61 00 63 00 61 00 64 00 62 00 72 00 61 00 2e 00 6a 00 70 00 67 00 } //02 00  abracadbra.jpg
		$a_01_3 = {69 00 64 00 73 00 3d 00 25 00 73 00 26 00 67 00 75 00 69 00 64 00 3d 00 25 00 73 00 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 3d 00 25 00 73 00 26 00 6e 00 74 00 69 00 64 00 3d 00 25 00 73 00 26 00 62 00 75 00 69 00 6c 00 64 00 3d 00 25 00 73 00 } //03 00  ids=%s&guid=%s&serial=%s&ntid=%s&build=%s
		$a_03_4 = {8b c1 99 f7 ff 42 0f 90 01 02 01 00 00 3b d7 0f 90 01 02 01 00 00 0f be 04 32 89 84 8c 90 01 02 00 00 89 4c 8c 90 01 01 41 81 f9 00 01 00 00 7c d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_3{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 3d 73 63 61 6e 66 69 6e 69 73 68 65 64 26 69 64 3d 25 73 00 } //05 00  畦据猽慣普湩獩敨♤摩┽s
		$a_01_1 = {65 78 70 6f 72 74 64 62 2e 70 68 70 3f 66 75 6e 63 3d 75 70 64 61 74 65 26 69 64 3d 25 73 26 70 69 64 3d 25 73 00 } //05 00  硥潰瑲扤瀮灨昿湵㵣灵慤整椦㵤猥瀦摩┽s
		$a_03_2 = {66 75 6e 63 3d 69 6e 73 74 61 6c 6c 26 90 03 01 01 70 75 69 64 3d 25 73 26 90 03 02 07 69 70 6c 61 6e 64 69 6e 67 3d 25 73 00 90 00 } //05 00 
		$a_01_3 = {35 38 39 3b 57 69 6e 33 32 2f 52 62 6f 74 2e 49 44 4e 3b 42 61 63 6b 64 6f 6f 72 3b 34 3b 57 69 6e 33 32 2f 52 62 6f 74 2e 49 44 4e 20 69 73 20 61 6e 20 49 52 43 20 63 6f 6e 74 72 6f 6c 6c 65 64 20 62 61 63 6b 64 6f 6f 72 } //02 00  589;Win32/Rbot.IDN;Backdoor;4;Win32/Rbot.IDN is an IRC controlled backdoor
		$a_01_4 = {76 62 61 73 65 2e 62 61 6b 00 } //02 00 
		$a_01_5 = {76 62 61 73 65 2e 64 61 74 00 } //02 00 
		$a_01_6 = {76 62 61 73 65 2e 74 6d 70 00 } //02 00 
		$a_01_7 = {55 70 64 61 74 65 20 64 6f 77 6e 6c 6f 61 64 20 63 6f 6d 70 6c 65 74 65 00 } //02 00 
		$a_01_8 = {45 72 72 6f 72 20 6f 63 63 75 72 73 20 77 68 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 75 70 64 61 74 65 3a 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_4{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 09 00 00 64 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 04 2e 77 69 6e 73 70 79 77 61 72 65 70 72 6f 74 65 63 74 90 02 02 2e 63 6f 6d 2f 90 02 0a 2f 49 6e 73 74 61 6c 6c 90 02 06 2e 65 78 65 90 00 } //64 00 
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 04 2e 57 69 6e 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 90 02 02 2e 63 6f 6d 2f 61 64 64 6f 6e 2f 90 00 } //64 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 90 02 04 2e 57 69 6e 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 90 02 02 2e 63 6f 6d 2f 73 74 61 74 2e 70 68 70 90 00 } //64 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 04 2e 6d 61 6c 77 61 72 72 69 6f 72 90 02 02 2e 63 6f 6d 2f 61 64 64 6f 6e 90 00 } //64 00 
		$a_02_4 = {68 74 74 70 3a 2f 2f 90 02 04 2e 6d 61 6c 77 61 72 72 69 6f 72 90 02 02 2e 63 6f 6d 2f 73 74 61 74 2e 70 68 70 90 00 } //01 00 
		$a_01_5 = {5c 41 64 73 6c 20 53 6f 66 74 77 61 72 65 20 4c 69 6d 69 74 65 64 5c 57 69 6e 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 } //01 00  \Adsl Software Limited\WinSpywareProtect
		$a_01_6 = {5c 41 64 73 6c 20 53 6f 66 74 77 61 72 65 20 4c 69 6d 69 74 65 64 5c 4d 61 6c 57 61 72 72 69 6f 72 } //01 00  \Adsl Software Limited\MalWarrior
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 41 64 73 6c 20 53 6f 66 74 77 61 72 65 20 4c 69 6d 69 74 65 64 5c 49 6e 73 74 61 6c 6c 65 72 } //01 00  Software\Adsl Software Limited\Installer
		$a_01_8 = {57 69 6e 53 70 79 77 61 72 65 50 72 6f 74 65 63 74 20 69 6e 73 74 61 6c 6c 65 72 } //00 00  WinSpywareProtect installer
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_5{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 72 6f 6a 61 6e 2e 46 6f 6c 64 65 72 66 75 21 73 64 35 20 69 73 20 61 20 6d 61 6c 69 63 69 6f 75 73 20 70 72 6f 67 72 61 6d 20 74 68 61 74 20 64 6f 65 73 20 6e 6f 74 20 69 6e 66 65 63 74 20 6f 74 68 65 72 20 66 69 6c 65 73 20 62 75 74 20 6d 61 79 20 72 65 70 72 65 73 65 6e 74 73 20 73 65 63 75 72 69 74 79 } //01 00  Trojan.Folderfu!sd5 is a malicious program that does not infect other files but may represents security
		$a_01_1 = {57 6f 72 6d 2e 53 6d 61 6c 6c 21 73 64 35 20 69 73 20 61 20 6e 65 74 77 6f 72 6b 2d 61 77 61 72 65 20 77 6f 72 6d 20 74 68 61 74 20 61 74 74 65 6d 70 74 73 20 74 6f 20 72 65 70 6c 69 63 61 74 65 20 61 63 72 6f 73 73 20 74 68 65 20 65 78 69 73 74 69 6e 67 20 6e 65 74 77 6f 72 6b 2e } //01 00  Worm.Small!sd5 is a network-aware worm that attempts to replicate across the existing network.
		$a_01_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 72 65 70 6f 72 74 73 20 74 68 61 74 20 25 73 20 69 73 20 6e 6f 74 20 72 65 67 69 73 74 65 72 65 64 } //01 00  Windows Security Center reports that %s is not registered
		$a_01_3 = {2c 25 73 20 73 63 61 6e 20 66 6f 72 20 6d 61 6c 77 61 72 65 20 61 6e 64 20 72 65 6d 6f 76 65 20 66 6f 75 6e 64 20 74 68 72 65 61 74 73 } //01 00  ,%s scan for malware and remove found threats
		$a_01_4 = {61 63 74 44 65 6c 65 74 65 56 69 72 75 73 45 78 65 63 75 74 65 25 } //01 00  actDeleteVirusExecute%
		$a_01_5 = {61 63 49 45 53 6e 69 66 66 65 72 31 57 42 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } //01 00  acIESniffer1WBFileDownload
		$a_01_6 = {43 3a 5c 54 45 4d 50 5c 55 70 67 72 61 64 65 72 33 2e 65 78 65 } //02 00  C:\TEMP\Upgrader3.exe
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 76 70 72 6f 2d 6c 61 62 73 2e 63 6f 6d 2f 62 75 79 2e 68 74 6d 6c } //00 00  http://www.avpro-labs.com/buy.html
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_6{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0e 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 00 62 00 72 00 61 00 63 00 61 00 64 00 62 00 72 00 61 00 2e 00 6a 00 70 00 67 00 00 00 } //02 00 
		$a_00_1 = {69 00 3d 00 25 00 73 00 26 00 67 00 3d 00 25 00 73 00 26 00 73 00 3d 00 25 00 73 00 26 00 6e 00 3d 00 25 00 73 00 26 00 62 00 3d 00 25 00 73 00 26 00 7a 00 3d 00 25 00 69 00 26 00 68 00 3d 00 25 00 69 00 26 00 6f 00 3d 00 4f 00 4b 00 } //02 00  i=%s&g=%s&s=%s&n=%s&b=%s&z=%i&h=%i&o=OK
		$a_00_2 = {25 00 73 00 73 00 6d 00 72 00 74 00 64 00 65 00 66 00 70 00 2e 00 65 00 78 00 65 00 00 00 } //02 00 
		$a_00_3 = {6b 6c 6a 68 66 6c 6b 37 33 23 4f 4f 23 2a 55 24 4f 28 2a 59 4f 00 } //01 00 
		$a_00_4 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 6e 00 20 00 70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 2c 00 20 00 70 00 6c 00 65 00 61 00 73 00 65 00 20 00 77 00 61 00 69 00 74 00 2e 00 2e 00 2e 00 } //01 00  Installation in progress, please wait...
		$a_81_5 = {2e 63 6f 6d 2f 64 70 2f 00 } //01 00 
		$a_00_6 = {70 00 69 00 63 00 2e 00 6a 00 70 00 67 00 00 00 } //01 00 
		$a_00_7 = {69 00 6e 00 66 00 6f 00 2e 00 6a 00 70 00 67 00 00 00 } //02 00 
		$a_00_8 = {77 00 3d 00 25 00 73 00 26 00 67 00 3d 00 25 00 73 00 26 00 78 00 3d 00 25 00 73 00 26 00 75 00 3d 00 25 00 73 00 26 00 6e 00 3d 00 25 00 73 00 26 00 70 00 3d 00 25 00 69 00 26 00 73 00 3d 00 25 00 69 00 26 00 6c 00 3d 00 4f 00 4b 00 } //01 00  w=%s&g=%s&x=%s&u=%s&n=%s&p=%i&s=%i&l=OK
		$a_81_9 = {2e 6e 65 74 2f 64 70 2f 00 } //01 00 
		$a_81_10 = {2e 69 6e 2f 64 70 2f 00 } //02 00  椮⽮灤/
		$a_00_11 = {25 00 73 00 73 00 64 00 70 00 2e 00 65 00 78 00 65 00 00 00 } //04 00 
		$a_03_12 = {6a 00 68 69 03 00 00 56 e8 90 01 04 83 c4 0c 81 ff 69 03 00 00 73 90 00 } //04 00 
		$a_03_13 = {53 68 69 03 00 00 50 e8 90 01 04 b8 69 03 00 00 83 c4 0c 39 85 90 01 04 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_7{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 32 42 44 2d 41 38 43 42 2d 37 45 35 } //01 00  42BD-A8CB-7E5
		$a_01_1 = {3a 2f 2f 64 6c 2e 25 73 2f 67 65 74 2f 3f 70 69 6e 3d } //01 00  ://dl.%s/get/?pin=
		$a_01_2 = {2f 73 63 61 6e 2e } //01 00  /scan.
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //00 00  InternetOpenA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_8{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {3c 2e 70 68 70 3f } //02 00  <.php?
		$a_01_1 = {62 2f 68 74 6d 6c 2c } //01 00  b/html,
		$a_01_2 = {54 00 55 00 4e 00 50 00 52 00 4f 00 54 00 45 00 43 00 54 00 45 00 44 00 43 00 4f 00 4e 00 46 00 49 00 52 00 4d 00 46 00 4f 00 52 00 4d 00 } //01 00  TUNPROTECTEDCONFIRMFORM
		$a_01_3 = {54 00 4e 00 45 00 54 00 41 00 54 00 54 00 41 00 43 00 4b 00 44 00 45 00 54 00 45 00 43 00 54 00 49 00 4f 00 4e 00 46 00 4f 00 52 00 4d 00 } //01 00  TNETATTACKDETECTIONFORM
		$a_01_4 = {53 00 43 00 41 00 4e 00 5f 00 49 00 4d 00 47 00 } //01 00  SCAN_IMG
		$a_01_5 = {54 00 56 00 49 00 52 00 55 00 53 00 44 00 45 00 53 00 43 00 46 00 4f 00 52 00 4d 00 } //00 00  TVIRUSDESCFORM
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_9{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 3d 69 6e 73 74 61 6c 6c 72 75 6e 26 69 64 3d 25 73 26 6c 61 6e 64 69 6e 67 3d 25 73 26 6c 61 6e 67 3d 25 73 26 73 75 62 3d 25 73 26 6e 6f 74 73 74 61 74 3d 31 } //01 00  func=installrun&id=%s&landing=%s&lang=%s&sub=%s&notstat=1
		$a_01_1 = {2f 70 61 79 2f 25 73 2f 25 73 2f } //01 00  /pay/%s/%s/
		$a_01_2 = {65 78 70 6f 72 74 64 62 2e 70 68 70 3f 66 75 6e 63 3d 75 70 64 61 74 65 26 69 64 3d 25 73 26 70 69 64 3d 25 73 } //01 00  exportdb.php?func=update&id=%s&pid=%s
		$a_01_3 = {41 4d 46 49 4c 45 53 3e 5c 73 6e 69 66 66 65 6d 5c 73 6e 69 66 66 65 6d 2e 65 78 65 } //01 00  AMFILES>\sniffem\sniffem.exe
		$a_01_4 = {ff ff ff ff 0c 00 00 00 4c 61 75 6e 63 68 65 72 2e 65 78 65 00 00 00 00 ff ff ff ff 0b 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 00 ff ff ff ff } //02 00 
		$a_01_5 = {3f 74 79 70 65 3d 25 73 26 70 69 6e 3d 25 73 26 6c 6e 64 3d 25 73 } //02 00  ?type=%s&pin=%s&lnd=%s
		$a_01_6 = {68 74 74 70 3a 2f 2f 64 6c 2e 00 00 ff ff ff ff 05 00 00 00 2f 67 65 74 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_10{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR,07 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 00 6e 00 74 00 69 00 73 00 70 00 79 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 2b 00 73 00 74 00 61 00 74 00 2e 00 70 00 68 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 25 00 64 00 26 00 61 00 66 00 66 00 69 00 64 00 3d 00 25 00 73 00 26 00 70 00 63 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 62 00 62 00 72 00 3d 00 25 00 73 00 00 00 } //01 00 
		$a_01_1 = {25 00 73 00 5c 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 50 00 72 00 6f 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_01_2 = {25 00 73 00 5c 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 4d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_01_3 = {41 00 6e 00 74 00 69 00 53 00 70 00 79 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 00 00 } //01 00 
		$a_01_4 = {50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00 } //01 00 
		$a_01_5 = {4e 00 6f 00 52 00 75 00 6e 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_WinSpywareProtect_11{
	meta:
		description = "Trojan:Win32/WinSpywareProtect,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 5c 4c 61 73 74 53 75 6e 20 4c 74 64 2e 5c 5c } //02 00  Software\\LastSun Ltd.\\
		$a_01_1 = {2c 25 73 20 73 63 61 6e 20 66 6f 72 20 6d 61 6c 77 61 72 65 20 61 6e 64 20 72 65 6d 6f 76 65 20 66 6f 75 6e 64 20 74 68 72 65 61 74 73 } //01 00  ,%s scan for malware and remove found threats
		$a_01_2 = {49 6c 6c 65 67 61 6c 20 61 63 74 69 76 61 74 69 6f 6e 20 63 6f 64 65 21 20 52 65 63 68 65 63 6b 20 79 6f 75 72 20 69 6e 70 75 74 20 64 61 74 61 21 } //01 00  Illegal activation code! Recheck your input data!
		$a_01_3 = {54 72 6f 6a 61 6e 2d 50 53 57 2e 47 4f 50 74 72 6f 6a 61 6e 21 73 64 35 20 69 73 20 61 20 6d 61 6c 69 63 69 6f 75 73 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 74 68 61 74 20 61 74 74 65 6d 70 74 73 20 74 6f 20 73 74 65 61 6c 20 70 61 73 73 77 6f 72 64 73 2c } //01 00  Trojan-PSW.GOPtrojan!sd5 is a malicious application that attempts to steal passwords,
		$a_01_4 = {49 4d 2d 46 6c 6f 6f 64 65 72 2e 54 6f 6f 6c 7a 59 32 4b 21 73 64 35 20 69 73 20 61 20 74 68 72 65 61 74 20 74 68 61 74 20 69 73 20 63 61 70 61 62 6c 65 20 74 6f 20 63 61 75 73 65 } //01 00  IM-Flooder.ToolzY2K!sd5 is a threat that is capable to cause
		$a_01_5 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 73 20 61 20 6e 65 77 20 61 6e 64 20 69 6d 70 72 6f 76 65 64 20 61 70 70 72 6f 61 63 68 20 74 6f 20 73 70 79 77 61 72 65 20 69 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 20 61 6e 64 20 72 65 6d 6f 76 61 6c 2e } //00 00  This program is a new and improved approach to spyware identification and removal.
	condition:
		any of ($a_*)
 
}