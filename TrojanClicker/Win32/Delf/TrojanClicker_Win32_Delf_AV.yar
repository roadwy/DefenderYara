
rule TrojanClicker_Win32_Delf_AV{
	meta:
		description = "TrojanClicker:Win32/Delf.AV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 68 61 74 69 73 6d 79 69 70 2e 63 6f 6d 2f 61 75 74 6f 6d 61 74 69 6f 6e 2f 6e 30 39 32 33 30 39 34 35 2e 61 73 70 } //01 00  http://www.whatismyip.com/automation/n09230945.asp
		$a_00_1 = {68 74 74 70 3a 2f 2f 6c 32 74 6f 70 2e 72 75 2f 76 6f 74 65 2f 25 64 2f } //01 00  http://l2top.ru/vote/%d/
		$a_02_2 = {b8 31 00 00 00 e8 90 01 04 ff 34 85 90 01 04 b8 0b 00 00 00 e8 90 01 04 ff 34 85 90 01 04 b8 38 00 00 00 e8 90 01 04 ff 34 85 90 01 04 8b c3 ba 03 00 00 00 e8 90 01 04 5b c3 90 00 } //01 00 
		$a_02_3 = {73 65 63 5f 72 65 66 65 72 65 72 3d 90 02 04 ff ff ff ff 09 00 00 00 76 6f 74 65 4f 6b 3d 6f 6b 90 02 20 6e 61 6d 65 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}