
rule Trojan_Win32_Agent_N{
	meta:
		description = "Trojan:Win32/Agent.N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a1 f8 82 40 00 64 8b 15 30 00 00 00 8b 42 0c 8b 70 1c 8b 16 8b 42 08 a3 2c 85 40 00 a1 1c 83 40 00 8d 05 1c 83 40 00 50 c3 a1 2c 85 40 00 85 c0 75 09 } //01 00 
		$a_01_1 = {8b 70 1c 8b 16 8b 42 08 a3 2c 85 40 00 a1 1c 83 40 00 8d 05 1c 83 40 00 50 c3 a1 2c 85 40 00 85 c0 75 09 33 c0 5e 8b e5 5d c2 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}