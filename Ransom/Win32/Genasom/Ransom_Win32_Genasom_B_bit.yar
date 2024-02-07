
rule Ransom_Win32_Genasom_B_bit{
	meta:
		description = "Ransom:Win32/Genasom.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //04 00  Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr
		$a_01_1 = {aa d5 e2 b8 f6 b3 cc d0 f2 c7 eb c8 cf d5 e6 d7 d0 cf b8 d4 c4 b6 c1 d2 d4 cf c2 bc b8 b5 e3 a3 } //01 00 
		$a_03_2 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 90 02 20 2f 61 64 64 90 00 } //01 00 
		$a_01_3 = {6e 65 74 20 75 73 65 72 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 2f 61 63 74 69 76 65 3a 6e 6f } //01 00  net user Administrator /active:no
		$a_03_4 = {6e 65 74 20 75 73 65 72 90 02 40 2f 61 64 64 90 00 } //01 00 
		$a_03_5 = {6e 65 74 20 75 73 65 72 90 02 40 2f 61 63 74 69 76 65 3a 79 65 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}