
rule Trojan_Win32_Zbot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 56 68 00 00 04 00 ff 15 90 01 03 00 8b 4c 24 10 83 c1 0a 51 6a 08 50 ff 15 90 01 03 00 ff 74 24 10 8b f8 53 57 e8 8c 36 00 00 83 c4 0c 56 56 57 ff 15 90 00 } //01 00 
		$a_01_1 = {31 35 36 2e 32 33 36 2e 37 30 2e 31 38 31 } //01 00  156.236.70.181
		$a_01_2 = {4c 6f 61 64 65 72 2e 64 61 74 } //00 00  Loader.dat
	condition:
		any of ($a_*)
 
}