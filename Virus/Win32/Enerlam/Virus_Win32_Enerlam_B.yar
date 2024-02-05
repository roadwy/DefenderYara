
rule Virus_Win32_Enerlam_B{
	meta:
		description = "Virus:Win32/Enerlam.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 58 8d 85 90 01 04 50 ff b5 90 01 04 e8 90 01 02 00 00 0b c0 0f 84 90 01 02 ff ff 81 bd 90 01 04 50 45 00 00 0f 85 90 01 02 ff ff 66 81 bd 90 01 04 ae ae 0f 84 90 01 02 ff ff 6a 00 6a 00 90 00 } //01 00 
		$a_02_1 = {f7 f1 40 f7 e1 89 85 90 01 04 8b 46 e8 03 46 ec 33 d2 f7 f1 40 f7 e1 89 85 90 01 04 8b 8d 90 01 04 8b 85 90 01 04 05 90 01 02 00 00 f7 f1 40 f7 e1 89 85 90 01 04 87 f7 b9 0a 00 00 00 f3 a5 90 00 } //01 00 
		$a_02_2 = {0b c0 0f 84 90 01 02 ff ff 66 c7 85 90 01 06 33 c0 66 8b 85 90 01 04 83 c0 18 89 85 90 01 04 8d 85 90 01 04 01 85 90 01 04 33 c0 33 d2 66 8b 85 90 01 04 b9 28 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}