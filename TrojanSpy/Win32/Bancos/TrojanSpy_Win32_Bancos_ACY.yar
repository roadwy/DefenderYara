
rule TrojanSpy_Win32_Bancos_ACY{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {bf 01 00 00 00 8b 45 f8 0f b6 44 38 ff 03 c6 b9 ff 00 00 00 99 f7 f9 8b da 8b 45 ec 3b 45 f0 7d 05 ff 45 ec eb 07 c7 45 ec 01 00 00 00 83 f3 10 } //01 00 
		$a_01_1 = {36 37 42 41 45 42 32 35 36 44 42 45 43 45 45 42 31 43 35 44 38 32 41 32 44 32 32 34 38 32 45 31 34 35 37 35 00 } //01 00 
		$a_01_2 = {34 35 38 38 46 39 37 36 43 41 32 41 35 41 44 45 35 45 43 32 33 34 42 30 00 } //01 00 
		$a_01_3 = {05 64 61 64 6f 73 } //00 00 
	condition:
		any of ($a_*)
 
}