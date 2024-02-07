
rule TrojanDropper_Win32_Nesgohn_B{
	meta:
		description = "TrojanDropper:Win32/Nesgohn.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 66 00 72 00 6f 00 6e 00 74 00 70 00 61 00 67 00 65 00 5c 00 77 00 69 00 6e 00 6e 00 65 00 72 00 2e 00 6a 00 70 00 67 00 } //01 00  Program Files\microsoft frontpage\winner.jpg
		$a_01_1 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 20 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 5c 00 6f 00 65 00 69 00 6d 00 70 00 6f 00 72 00 74 00 2e 00 6a 00 70 00 67 00 } //01 00  Program Files\Outlook Express\oeimport.jpg
		$a_01_2 = {44 00 3a 00 5c 00 73 00 68 00 65 00 6e 00 6c 00 6f 00 6e 00 67 00 } //01 00  D:\shenlong
		$a_01_3 = {50 00 65 00 6e 00 64 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 52 00 65 00 6e 00 61 00 6d 00 65 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 73 00 } //00 00  PendingFileRenameOperations
	condition:
		any of ($a_*)
 
}