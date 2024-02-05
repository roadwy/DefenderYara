
rule Backdoor_Win32_PcClient_ZT_dll{
	meta:
		description = "Backdoor:Win32/PcClient.ZT!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 c2 2c 35 00 00 40 3b c1 89 15 90 01 04 7c dc 90 00 } //01 00 
		$a_03_1 = {8b 50 3c 81 c5 90 01 01 3e 00 00 89 0d 90 01 04 89 2d 90 01 04 8b 54 02 50 83 c2 f8 90 00 } //01 00 
		$a_01_2 = {81 3c 01 12 65 12 76 75 06 39 5c 01 04 74 07 41 3b ca 72 ec } //00 00 
	condition:
		any of ($a_*)
 
}