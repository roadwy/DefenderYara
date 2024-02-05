
rule TrojanSpy_Win32_Bafi_D{
	meta:
		description = "TrojanSpy:Win32/Bafi.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 41 00 4e 00 4b 00 00 00 00 00 44 00 45 00 55 00 00 00 57 00 00 00 55 72 6c 00 2e 00 68 00 74 00 6d } //01 00 
		$a_01_1 = {74 00 70 00 61 00 63 00 5f 00 25 00 64 00 2e 00 6d 00 76 00 74 00 } //01 00 
		$a_01_2 = {5f 00 69 00 66 00 72 00 6d 00 2e 00 68 00 74 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}