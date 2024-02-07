
rule MonitoringTool_MSIL_GuardSpy{
	meta:
		description = "MonitoringTool:MSIL/GuardSpy,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 47 75 61 72 64 20 53 70 79 20 73 65 74 75 70 20 6f 72 69 67 69 6e 61 6c 5c 47 75 61 72 64 20 53 70 79 20 73 65 74 75 70 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 47 75 61 72 64 20 53 70 79 20 73 65 74 75 70 20 65 73 70 2e 70 64 62 } //01 00  D:\Guard Spy setup original\Guard Spy setup\obj\x86\Release\Guard Spy setup esp.pdb
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 65 00 61 00 74 00 75 00 66 00 61 00 6d 00 69 00 6c 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } //01 00  cmd.exe /c start  http://www.monitoreatufamilia.com
		$a_01_2 = {43 00 3a 00 5c 00 6d 00 79 00 73 00 71 00 6c 00 5c 00 65 00 78 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  C:\mysql\ext.exe
		$a_01_3 = {47 00 75 00 61 00 72 00 64 00 5f 00 5f 00 5f 00 53 00 70 00 79 00 } //00 00  Guard___Spy
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}