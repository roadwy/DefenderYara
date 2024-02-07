
rule Trojan_Win32_Kolweb_P{
	meta:
		description = "Trojan:Win32/Kolweb.P,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 } //01 00  Set FileSystemObject = CreateObject("scripting.filesystemobject")
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 6f 6f 6c 62 61 72 } //01 00  Software\Microsoft\Internet Explorer\Toolbar
		$a_00_4 = {53 65 74 20 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set Shell = CreateObject("Wscript.Shell")
		$a_02_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 90 02 10 2e 65 78 65 90 00 } //01 00 
		$a_00_6 = {65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //01 00  exefile\shell\Open\Command
		$a_00_7 = {70 69 66 66 69 6c 65 5c 73 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //00 00  piffile\shell\Open\Command
	condition:
		any of ($a_*)
 
}