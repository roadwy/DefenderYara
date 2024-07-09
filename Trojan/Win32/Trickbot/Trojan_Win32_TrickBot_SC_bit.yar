
rule Trojan_Win32_TrickBot_SC_bit{
	meta:
		description = "Trojan:Win32/TrickBot.SC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 83 39 01 75 ?? 8b 51 14 8b 41 10 8b fb 2b fa 3b f8 } //1
		$a_03_1 = {8b 74 24 18 8b 45 00 8b fe 85 c0 74 ?? 66 83 38 01 75 ?? 8b 50 14 8b 48 10 8b f3 2b f2 3b f1 72 } //1
		$a_03_2 = {8b 4d 00 8b 51 0c 66 0f b6 34 02 66 2b f7 70 ?? 66 85 f6 7d ?? 66 81 c6 00 01 70 ?? 85 c9 74 ?? 66 83 39 01 75 16 8b 51 14 8b 41 10 8b fb 2b fa 3b f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}