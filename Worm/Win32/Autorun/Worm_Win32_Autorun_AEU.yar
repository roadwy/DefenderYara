
rule Worm_Win32_Autorun_AEU{
	meta:
		description = "Worm:Win32/Autorun.AEU,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 2f 65 78 70 6c 6f 72 65 2f 63 6f 6d 6d 61 6e 64 3d 90 02 0b 61 75 74 6f 72 75 6e 2e 69 6e 66 90 00 } //01 00 
		$a_02_1 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 90 02 0c 5c 73 76 63 68 6f 73 74 2e 65 78 65 90 00 } //01 00 
		$a_02_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 90 02 0b 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 90 00 } //01 00 
		$a_00_3 = {73 6d 74 70 2e 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 2e 75 6b } //01 00  smtp.mail.yahoo.co.uk
		$a_00_4 = {5b 43 74 72 6c 5d } //01 00  [Ctrl]
		$a_00_5 = {5b 45 73 63 5d } //01 00  [Esc]
		$a_00_6 = {6b 69 6c 6c 20 65 6e 65 6d 61 79 } //01 00  kill enemay
		$a_00_7 = {5c 4e 65 77 56 65 72 53 69 6f 6e 2e 73 79 73 } //00 00  \NewVerSion.sys
	condition:
		any of ($a_*)
 
}