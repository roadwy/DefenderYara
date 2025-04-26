
rule TrojanSpy_Win32_Agent_TB{
	meta:
		description = "TrojanSpy:Win32/Agent.TB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 7d f0 a5 a0 ?? ?? 00 10 a5 a5 ?? ?? a4 80 45 f1 ?? 80 45 f2 ?? 80 45 f3 ?? 80 45 ?? ?? 80 45 ?? ?? 80 45 } //1
		$a_02_1 = {32 35 30 00 65 ?? ?? 00 25 73 3c 25 73 3e } //1
		$a_00_2 = {32 35 30 00 65 32 38 00 71 75 69 74 } //1 㔲0㉥8畱瑩
		$a_00_3 = {44 6e 73 51 75 65 72 79 5f 41 } //1 DnsQuery_A
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}