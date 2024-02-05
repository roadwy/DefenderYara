
rule TrojanDropper_Win32_Potao_A{
	meta:
		description = "TrojanDropper:Win32/Potao.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 6a 00 bb 80 00 00 00 53 6a 01 6a 00 6a 01 be 00 00 00 c0 56 8d 8d 90 01 02 ff ff 51 89 45 90 01 01 ff d0 6a 00 53 6a 01 6a 00 6a 01 89 45 fc 56 8d 85 90 01 02 ff ff 50 ff 55 90 00 } //01 00 
		$a_01_1 = {48 8d bd fe fe ff ff 8d b5 fc fe ff ff 89 45 fc 33 d2 2b fb 8b c3 2b f3 8a 08 66 c7 44 07 ff 00 00 80 f9 0d 75 05 88 0c 06 } //00 00 
	condition:
		any of ($a_*)
 
}