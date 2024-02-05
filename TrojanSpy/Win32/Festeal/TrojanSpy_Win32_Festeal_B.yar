
rule TrojanSpy_Win32_Festeal_B{
	meta:
		description = "TrojanSpy:Win32/Festeal.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ec 83 ec 3c a1 00 e0 40 00 33 c5 89 45 fc 56 57 6a 06 59 be 68 20 0e 8d 7d e0 7f c6 be fb f3 } //00 00 
	condition:
		any of ($a_*)
 
}