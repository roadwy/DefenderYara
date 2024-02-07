
rule Trojan_Win32_Agent_RF_dll{
	meta:
		description = "Trojan:Win32/Agent.RF!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b1 6c 32 c0 c6 45 e0 73 c6 45 e1 68 88 4d e2 c6 45 e3 77 88 45 e4 88 45 e5 c6 45 e6 69 c6 45 e7 2e c6 45 e8 64 88 4d e9 88 4d ea 88 45 eb 90 90 c6 45 e4 61 c6 45 e5 70 } //01 00 
		$a_01_1 = {25 73 5c 25 7a 34 5e 3c 64 2e 6c 6e 6b } //01 00  %s\%z4^<d.lnk
		$a_01_2 = {55 7a 34 5e 3c 52 4c 44 7a 34 5e 3c 6f 77 6e 7a 34 5e 3c 6c 6f 61 7a 34 5e 3c 64 54 6f 46 69 6c 65 41 } //00 00  Uz4^<RLDz4^<ownz4^<loaz4^<dToFileA
	condition:
		any of ($a_*)
 
}