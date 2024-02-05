
rule TrojanSpy_Win32_Bancos_ACX{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {bf 01 00 00 00 8b 45 f8 0f b6 44 38 ff 03 c6 b9 ff 00 00 00 99 f7 f9 8b da 8b 45 ec 3b 45 f0 7d 05 ff 45 ec eb 07 c7 45 ec 01 00 00 00 83 f3 10 } //01 00 
		$a_01_1 = {37 31 41 35 31 37 36 42 43 41 32 45 35 45 44 32 32 38 35 38 41 39 30 41 36 36 44 46 35 33 41 34 30 39 36 32 43 38 32 38 38 42 46 37 00 } //01 00 
		$a_01_2 = {44 31 32 34 39 37 31 33 35 31 41 33 31 37 39 32 00 } //01 00 
		$a_01_3 = {09 54 41 44 4f 51 75 65 72 79 08 63 6f 6e 74 61 64 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}