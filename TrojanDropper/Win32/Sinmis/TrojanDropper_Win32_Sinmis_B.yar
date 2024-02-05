
rule TrojanDropper_Win32_Sinmis_B{
	meta:
		description = "TrojanDropper:Win32/Sinmis.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 65 78 65 c6 80 90 01 04 00 31 c0 6a 04 68 90 01 04 ff 15 90 01 04 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 68 90 01 04 ff 15 90 00 } //01 00 
		$a_03_1 = {31 c0 6a 00 68 90 01 04 68 90 01 04 e8 90 01 02 00 00 4d 5a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}