
rule Backdoor_Win32_Hostposer_A{
	meta:
		description = "Backdoor:Win32/Hostposer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d6 68 2c 90 01 01 40 00 68 28 90 01 01 40 00 68 24 90 01 01 40 00 8d 90 01 03 e8 90 01 02 00 00 90 09 08 00 ba 90 01 02 40 00 8d 4d 90 00 } //01 00 
		$a_01_1 = {8b 55 e0 66 81 e3 ff 00 8b f8 89 55 84 c7 85 7c ff ff ff 08 00 00 00 79 09 66 4b 66 81 cb 00 ff 66 43 0f bf c3 8d 4d bc } //00 00 
	condition:
		any of ($a_*)
 
}