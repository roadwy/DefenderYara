
rule TrojanSpy_Win32_Ploscato_C{
	meta:
		description = "TrojanSpy:Win32/Ploscato.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 80 34 08 4d 41 83 f9 46 7c f3 } //01 00 
		$a_01_1 = {83 f2 21 89 95 ec ff fd ff 83 fa 1c 74 17 83 fa 65 74 12 83 fa 7f 74 0d b2 01 d2 e2 f6 d2 20 10 } //01 00 
		$a_03_2 = {72 bf 33 ff 0f b6 05 90 01 04 50 0f b6 87 90 01 04 50 e8 90 01 04 32 05 90 01 04 47 88 87 90 01 04 59 59 81 ff 0c 01 00 00 72 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}