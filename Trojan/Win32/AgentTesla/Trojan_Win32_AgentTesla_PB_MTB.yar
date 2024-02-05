
rule Trojan_Win32_AgentTesla_PB_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {8d 84 24 2c 02 00 00 ff d0 ff 15 00 00 40 00 6a 00 6a 00 ff 15 00 00 40 00 5f 5e 33 c0 5b 8b e5 5d c3 } //05 00 
		$a_00_1 = {8d 44 24 24 ff d0 ff 15 00 00 40 00 6a 00 6a 00 ff 15 00 00 40 00 5f 5e 33 c0 5b 8b e5 5d c3 } //01 00 
		$a_00_2 = {0f b6 44 3c 18 0f b6 c9 03 c8 0f b6 c1 8b 4c 24 10 8a 44 04 18 30 84 0c 18 02 00 00 } //01 00 
		$a_02_3 = {0f b6 84 14 90 01 02 00 00 0f b6 c9 03 c8 0f b6 c1 0f b6 84 04 90 01 02 00 00 30 44 3c 10 90 00 } //01 00 
		$a_00_4 = {8a d1 80 f2 04 88 14 01 41 81 f9 00 e1 f5 05 72 ef } //01 00 
		$a_00_5 = {8a ca 80 f1 04 88 0c 02 42 81 fa 00 e1 f5 05 72 ef } //00 00 
	condition:
		any of ($a_*)
 
}