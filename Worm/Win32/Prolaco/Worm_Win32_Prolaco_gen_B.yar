
rule Worm_Win32_Prolaco_gen_B{
	meta:
		description = "Worm:Win32/Prolaco.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 10 8b 45 08 31 d0 88 01 ff 45 f8 8b 45 f8 3b 45 10 72 } //02 00 
		$a_03_1 = {83 e8 32 3b 45 90 01 01 7d 0d 8b 45 90 01 01 83 c0 32 3b 45 90 01 01 7e 02 eb 90 00 } //01 00 
		$a_03_2 = {ff ff 3c 61 74 90 01 01 8a 85 90 01 02 ff ff 3c 62 74 90 01 01 83 ec 90 01 01 8d 85 90 01 02 ff ff 50 e8 90 01 04 83 c4 90 01 01 83 f8 02 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}