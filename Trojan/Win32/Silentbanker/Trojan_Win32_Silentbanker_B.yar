
rule Trojan_Win32_Silentbanker_B{
	meta:
		description = "Trojan:Win32/Silentbanker.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 54 53 56 57 6a 06 59 be 90 01 04 8d 7d e4 f3 a5 66 a5 a4 6a 06 59 be 90 01 04 8d 7d c8 f3 a5 8b 5d 08 66 a5 a4 6a 06 59 be 90 01 04 8d 7d ac f3 a5 66 a5 8d 45 e4 53 50 a4 e8 90 01 02 ff ff 85 c0 59 59 74 14 8d 4d e4 2b c1 83 c0 90 01 01 99 6a 1a 59 f7 f9 8a 44 15 e4 eb 4a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Silentbanker_B_2{
	meta:
		description = "Trojan:Win32/Silentbanker.B,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 54 24 04 8d 0c 40 8d 0c 88 c1 e1 04 03 c8 c1 e1 08 2b c8 8d 84 88 c3 9e 26 00 8b c8 c1 e9 10 0f af ca c1 e9 10 74 dc a3 90 01 04 8b c1 c2 04 00 90 09 0f 00 a1 90 01 04 85 c0 75 06 ff 15 90 00 } //0a 00 
		$a_02_1 = {b9 fb 03 00 00 b8 20 20 20 20 bf 90 01 04 f3 ab 66 ab bf ee 0f 00 00 c7 44 24 10 00 00 00 00 8b 44 24 10 8b 74 24 1c d1 e8 f6 c4 01 89 44 24 10 75 1b 90 00 } //0a 00 
		$a_00_2 = {25 73 25 78 25 78 2e 64 61 74 } //00 00  %s%x%x.dat
	condition:
		any of ($a_*)
 
}