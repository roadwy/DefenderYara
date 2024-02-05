
rule TrojanSpy_Win32_Rebhip_D_dll{
	meta:
		description = "TrojanSpy:Win32/Rebhip.D!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 58 5f 50 52 4f 58 59 5f 53 45 52 56 45 52 5f 58 78 } //01 00 
		$a_01_1 = {66 75 6e 63 6f 65 73 2e 64 6c 6c 00 45 6e 76 69 61 72 53 74 72 65 61 6d 00 47 65 74 43 68 72 6f 6d 65 50 61 73 73 00 47 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 00 47 65 74 43 75 72 72 65 6e 74 4d 53 4e 53 65 74 74 69 6e 67 73 00 47 65 74 4d 53 4e 53 74 61 74 75 73 00 4d 6f 7a 69 6c 6c 61 33 5f 35 50 61 73 73 77 6f 72 64 00 53 65 74 4d 53 4e 53 74 61 74 75 73 00 53 74 61 72 74 48 74 74 70 50 72 6f 78 79 } //01 00 
		$a_01_2 = {66 75 6e 63 6f 65 73 2e 64 6c 6c 00 45 6e 76 69 61 72 53 74 72 65 61 6d 00 53 74 61 72 74 48 74 74 70 50 72 6f 78 79 00 53 74 61 72 74 53 6f 63 6b 73 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}