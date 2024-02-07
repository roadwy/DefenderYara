
rule Trojan_Win32_Longwatch_MTB{
	meta:
		description = "Trojan:Win32/Longwatch!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 6c 6f 67 2e 74 78 74 } //c:\windows\temp\log.txt  01 00 
		$a_81_1 = {2d 2d 2d 2d 2d 2d 43 4c 49 50 42 4f 41 52 44 2d 2d 2d 2d } //01 00  ------CLIPBOARD----
		$a_81_2 = {5b 45 4e 54 45 52 5d } //01 00  [ENTER]
		$a_81_3 = {5b 50 52 49 4e 54 20 53 43 52 45 45 4e 5d } //01 00  [PRINT SCREEN]
		$a_81_4 = {5b 53 4c 45 45 50 5d } //01 00  [SLEEP]
		$a_81_5 = {5b 43 61 70 73 4c 6f 63 6b 5d } //01 00  [CapsLock]
		$a_81_6 = {5b 50 41 47 45 5f 55 50 5d } //01 00  [PAGE_UP]
		$a_81_7 = {5b 4c 45 46 54 5d } //00 00  [LEFT]
	condition:
		any of ($a_*)
 
}