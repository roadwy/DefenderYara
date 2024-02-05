
rule TrojanSpy_Win32_Pophot_H_dll{
	meta:
		description = "TrojanSpy:Win32/Pophot.H!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00 
		$a_00_1 = {63 3a 5c 64 6f 77 6e 66 00 00 00 00 ff ff ff ff 04 00 00 00 2e 62 61 74 00 00 00 00 ff ff ff ff } //01 00 
		$a_00_2 = {ff ff ff ff 02 00 00 00 64 6f 00 00 ff ff ff ff 04 00 00 00 6b 69 6c 6c 00 00 00 00 ff ff ff ff 01 00 00 00 30 00 00 00 ff ff ff ff 03 00 00 00 76 65 72 00 ff ff ff ff 06 00 00 00 6d 79 64 6f 77 6e } //01 00 
		$a_02_3 = {8b d8 8b 45 f4 50 8d 45 bc 50 b9 90 01 04 ba 90 01 04 b8 90 01 04 e8 90 01 04 6a 02 e8 90 01 04 e8 90 01 04 33 d2 52 50 8b c3 99 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}