
rule Trojan_Win32_Delf_CM{
	meta:
		description = "Trojan:Win32/Delf.CM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 00 00 ff ff ff ff 22 00 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //01 00 
		$a_01_1 = {6e 65 74 73 76 63 73 00 ff ff ff ff 34 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00 
		$a_01_2 = {45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 00 ff ff ff ff 09 00 00 00 54 53 45 6e 61 62 6c 65 64 } //01 00 
		$a_00_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 } //01 00  SYSTEM\CurrentControlSet\Control\Terminal Server
		$a_01_4 = {5c 50 61 72 61 6d 65 74 65 72 73 00 ff ff ff ff 0a 00 00 00 53 65 72 76 69 63 65 44 6c 6c } //01 00 
		$a_01_5 = {43 6f 6d 73 70 65 63 00 ff ff ff ff 09 00 00 00 20 2f 63 20 64 65 6c 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Delf_CM_2{
	meta:
		description = "Trojan:Win32/Delf.CM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 44 6c 6c 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //01 00  敓癲捩䑥汬搮汬匀牥楶散慍湩
		$a_01_1 = {6e 65 74 73 76 63 73 00 ff ff ff ff 34 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00 
		$a_00_2 = {68 74 6f 6e 73 } //01 00  htons
		$a_00_3 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //01 00  RegisterServiceCtrlHandlerA
		$a_00_4 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_5 = {6d 6f 75 73 65 5f 65 76 65 6e 74 } //01 00  mouse_event
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_00_7 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //00 00  OpenClipboard
	condition:
		any of ($a_*)
 
}