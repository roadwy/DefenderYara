
rule Worm_Win32_SnowFlake_A{
	meta:
		description = "Worm:Win32/SnowFlake.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 69 6d 65 2e 69 6e 69 00 } //01 00 
		$a_00_1 = {d4 cb d0 d0 ca b1 bc e4 3a 25 64 2d 25 64 2d 25 64 20 25 64 3a 25 64 3a 25 64 00 } //03 00 
		$a_03_2 = {83 c2 01 89 95 90 01 04 83 bd 90 01 04 64 7d 90 01 01 8b 85 90 01 04 03 85 90 01 04 89 85 90 01 04 8b 8d 90 01 04 83 c1 01 89 8d 90 01 04 81 bd 90 01 04 70 17 00 00 75 90 01 01 8b f4 ff 95 90 01 04 3b f4 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}