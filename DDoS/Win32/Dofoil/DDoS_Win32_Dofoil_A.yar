
rule DDoS_Win32_Dofoil_A{
	meta:
		description = "DDoS:Win32/Dofoil.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 06 ac 32 c2 aa e2 fa 61 8b 45 f4 8b e5 5d c3 } //2
		$a_01_1 = {81 c7 04 05 00 00 b8 56 71 64 4f ab b8 23 65 65 6c ab } //2
		$a_03_2 = {8b 75 08 6a 06 56 a1 ?? ?? ?? ?? 8b (40 ?? 80 ??|?? ?? ?? ff) d0 68 00 04 00 00 e8 ?? ?? ?? ?? 8b d8 68 00 04 00 00 53 } //2
		$a_01_3 = {c7 45 f8 68 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}