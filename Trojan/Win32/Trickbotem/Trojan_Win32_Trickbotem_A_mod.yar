
rule Trojan_Win32_Trickbotem_A_mod{
	meta:
		description = "Trojan:Win32/Trickbotem.A!mod,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 72 61 62 62 65 64 20 25 73 20 66 72 6f 6d 20 49 6e 62 6f 78 } //01 00  Grabbed %s from Inbox
		$a_81_1 = {47 72 61 62 62 65 64 20 25 73 20 66 72 6f 6d 20 43 6f 6e 74 61 63 74 73 } //01 00  Grabbed %s from Contacts
		$a_81_2 = {45 72 72 6f 72 20 68 69 64 69 6e 67 20 4f 75 74 6c 6f 6f 6b 20 66 72 6f 6d 20 74 68 65 20 74 61 73 6b 62 61 72 } //01 00  Error hiding Outlook from the taskbar
		$a_81_3 = {48 69 64 65 20 4f 75 74 6c 6f 6f 6b 20 66 72 6f 6d 20 73 79 73 74 65 6d 20 74 72 61 79 } //01 00  Hide Outlook from system tray
		$a_81_4 = {53 74 61 72 74 4f 75 74 6c 6f 6f 6b 28 29 3a 20 62 65 66 6f 72 65 20 68 69 64 65 } //01 00  StartOutlook(): before hide
		$a_81_5 = {63 3a 5c 74 65 6d 70 5c 6d 61 69 6c 2e 6c 6f 67 } //01 00  c:\temp\mail.log
		$a_81_6 = {53 74 61 72 74 4f 75 74 6c 6f 6f 6b 28 29 3a 20 53 68 65 6c 6c 45 78 65 63 75 74 65 57 28 29 20 20 25 53 20 25 53 } //00 00  StartOutlook(): ShellExecuteW()  %S %S
	condition:
		any of ($a_*)
 
}