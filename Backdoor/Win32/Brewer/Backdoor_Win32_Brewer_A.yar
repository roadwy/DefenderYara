
rule Backdoor_Win32_Brewer_A{
	meta:
		description = "Backdoor:Win32/Brewer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8d 74 26 00 8d bc 27 00 00 00 00 8b 31 83 c1 04 8d 96 ff fe fe fe f7 d6 21 f2 89 d0 25 80 80 80 80 74 e8 81 e2 80 80 00 00 75 06 c1 e8 10 83 c1 02 00 c0 } //1
		$a_02_1 = {fc b9 06 00 00 00 83 ec 10 f3 a6 0f 85 ?? ?? ff ff 31 ff be 00 04 00 00 8d 9d ?? ?? ff ff 89 74 24 08 89 7c 24 04 31 ff 89 1c 24 bb 01 00 00 00 e8 ?? ?? 00 00 8b b5 ?? ?? ff ff 31 d2 b9 ?? ?? ?? ?? 89 54 24 0c b8 0f 00 00 00 89 4c 24 04 89 44 24 08 89 34 24 } //1
		$a_00_2 = {2f 43 20 25 73 00 63 6d 64 2e 65 78 65 00 72 61 6e 0d 0a 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}