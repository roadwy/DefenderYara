
rule TrojanSpy_Win32_Bancos_ABT{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d8 83 fb 01 0f 8c 74 09 00 00 8d 45 f8 50 8d 55 f0 8b 45 fc } //01 00 
		$a_01_1 = {05 55 6e 69 74 78 00 } //01 00 
		$a_01_2 = {06 54 46 6f 72 6d 31 8b } //00 00 
	condition:
		any of ($a_*)
 
}