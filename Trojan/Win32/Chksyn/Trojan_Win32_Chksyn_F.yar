
rule Trojan_Win32_Chksyn_F{
	meta:
		description = "Trojan:Win32/Chksyn.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c9 35 4e 5a 01 83 c1 01 89 0d 90 01 03 00 8b 15 90 01 03 00 c1 ea 10 0f b7 c2 25 ff ff 00 00 90 00 } //01 00 
		$a_00_1 = {4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 45 78 70 6c 6f 72 65 72 22 20 6d 6f 64 65 20 3d 20 45 4e 41 42 4c 45 } //01 00  Microsoft Windows Explorer" mode = ENABLE
		$a_00_2 = {53 65 72 76 69 63 65 22 20 6d 6f 64 65 20 3d 20 45 4e 41 42 4c 45 } //01 00  Service" mode = ENABLE
		$a_03_3 = {6a f1 6a fe ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_00_4 = {c6 45 ec e9 8b 45 0c 2b 45 08 83 e8 05 89 45 ed } //00 00 
	condition:
		any of ($a_*)
 
}