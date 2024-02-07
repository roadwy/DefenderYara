
rule Trojan_Win32_Delf_FC{
	meta:
		description = "Trojan:Win32/Delf.FC,SIGNATURE_TYPE_PEHSTR_EXT,7f 01 7f 01 11 00 00 64 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //64 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //32 00  \Internet Explorer\IEXPLORE.EXE
		$a_00_2 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //32 00  AVP.Product_Notification
		$a_00_3 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d } //0a 00  AVP.TrafficMonConnectionTerm
		$a_00_4 = {73 79 73 6e 73 2e 64 6c 6c } //0a 00  sysns.dll
		$a_00_5 = {53 65 72 76 69 63 65 44 6c 6c } //0a 00  ServiceDll
		$a_00_6 = {75 73 65 72 69 6e 69 74 2e 65 78 65 } //0a 00  userinit.exe
		$a_00_7 = {63 6d 64 20 2f 63 20 64 65 6c 20 } //0a 00  cmd /c del 
		$a_00_8 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 } //0a 00  svchost.exe -k 
		$a_02_9 = {70 6c 75 67 69 6e 5c 90 02 08 2e 64 6c 6c 90 00 } //0a 00 
		$a_00_10 = {72 65 6d 6f 74 65 20 6e 65 74 77 6f 72 6b } //0a 00  remote network
		$a_00_11 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00  OpenSCManagerA
		$a_00_12 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //01 00  DisableRegistryTools
		$a_00_13 = {5c 68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  \htmlfile\shell\open\command
		$a_00_14 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 6e 65 74 6e 73 } //01 00  SYSTEM\CurrentControlSet\Services\netns
		$a_00_15 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_00_16 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //00 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
	condition:
		any of ($a_*)
 
}