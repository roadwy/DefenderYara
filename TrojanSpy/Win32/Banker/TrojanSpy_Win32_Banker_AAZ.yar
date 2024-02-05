
rule TrojanSpy_Win32_Banker_AAZ{
	meta:
		description = "TrojanSpy:Win32/Banker.AAZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 67 00 65 00 74 00 2e 00 61 00 73 00 70 00 3f 00 61 00 67 00 3d 00 } //01 00 
		$a_01_1 = {26 00 63 00 61 00 6d 00 70 00 6f 00 31 00 30 00 3d 00 } //01 00 
		$a_01_2 = {43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00 } //01 00 
		$a_01_3 = {b8 04 00 02 80 89 0b 8b 4d bc 52 89 4b 04 89 43 08 8b 45 c4 89 43 0c ff 56 34 85 c0 db e2 7d 12 } //00 00 
	condition:
		any of ($a_*)
 
}