
rule Trojan_Win32_Nivdort_A_dll{
	meta:
		description = "Trojan:Win32/Nivdort.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 78 07 45 75 0e 80 78 08 58 75 08 80 78 09 45 75 02 } //2
		$a_03_1 = {83 e9 05 c6 04 08 32 8d 85 ?? ?? ff ff 50 ff 15 } //1
		$a_01_2 = {c6 45 f0 49 c6 45 f1 45 c6 45 f2 58 c6 45 f3 50 c6 45 f4 4c c6 45 f5 4f c6 45 f6 52 c6 45 f7 45 } //1
		$a_01_3 = {c6 45 e0 46 c6 45 e1 49 c6 45 e2 52 c6 45 e3 45 c6 45 e4 46 c6 45 e5 4f c6 45 e6 58 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}