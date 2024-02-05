
rule Virus_Win32_Expiro_MH_bit{
	meta:
		description = "Virus:Win32/Expiro.MH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4a 30 8b 31 81 e6 df 00 df 00 8b 49 0b 03 ce c1 e1 02 81 e9 } //01 00 
		$a_03_1 = {8b f0 8b 30 85 f6 81 f6 90 01 04 39 f1 89 32 01 d6 49 83 c0 04 49 49 49 81 c2 04 00 00 00 83 f9 00 75 dc 90 00 } //01 00 
		$a_01_2 = {89 c1 03 3c 91 89 7d e4 b8 24 00 00 00 99 f7 fb 8b 7d f4 8b 3c 87 89 7d dc } //00 00 
	condition:
		any of ($a_*)
 
}