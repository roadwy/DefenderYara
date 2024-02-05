
rule Backdoor_Win32_Nosrawec_A{
	meta:
		description = "Backdoor:Win32/Nosrawec.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 68 a1 0f 00 00 8d 85 90 01 02 ff ff 50 53 e8 90 01 04 85 c0 0f 8e 90 00 } //01 00 
		$a_03_1 = {b8 09 00 00 00 e8 90 01 04 40 69 c0 e8 03 00 00 50 b8 f4 01 00 00 e8 90 01 04 5a 03 d0 89 55 f8 90 00 } //01 00 
		$a_03_2 = {83 7d f8 00 74 0d 8b 55 f8 a1 90 01 04 8b 08 ff 51 38 8b 45 f8 e8 90 01 04 8b c8 83 c1 04 8d 45 fc ba 01 00 00 00 e8 90 01 04 83 7d fc 00 75 ac 90 00 } //01 00 
		$a_01_3 = {ff 53 0c 8b d8 85 db 74 3e 6a 00 68 41 1f 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}