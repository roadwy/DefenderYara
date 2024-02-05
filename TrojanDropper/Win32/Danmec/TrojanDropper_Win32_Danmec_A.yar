
rule TrojanDropper_Win32_Danmec_A{
	meta:
		description = "TrojanDropper:Win32/Danmec.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 ff d6 8d 4d 90 01 01 51 a3 90 01 04 c7 45 90 1b 00 90 01 04 c7 45 90 01 05 c7 45 90 01 05 88 5d 90 01 01 e8 90 01 04 83 c4 04 50 ff d6 90 00 } //01 00 
		$a_03_1 = {ff ff 52 ff 15 90 01 04 68 88 13 00 00 ff 15 90 09 0b 00 51 ff 15 90 01 04 8d 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}