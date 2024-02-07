
rule Trojan_Win32_Killav_FN{
	meta:
		description = "Trojan:Win32/Killav.FN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //02 00  keybd_event
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 6f 72 6b 5c 43 6f 6e 6e 65 63 74 69 6f 6e 73 5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //02 00  Microsoft\Network\Connections\pbk\rasphone.pbk
		$a_01_2 = {5b 43 61 70 73 4c 6f 63 6b 5d } //02 00  [CapsLock]
		$a_01_3 = {3a 5d 25 64 2d 25 64 2d 25 64 20 20 25 64 3a 25 64 3a 25 64 } //02 00  :]%d-%d-%d  %d:%d:%d
		$a_01_4 = {25 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //00 00  %s\shell\open\command
	condition:
		any of ($a_*)
 
}