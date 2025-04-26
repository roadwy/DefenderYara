
rule Backdoor_Win32_Zegost_EF_bit{
	meta:
		description = "Backdoor:Win32/Zegost.EF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 d0 44 c6 45 d1 6c c6 45 d2 6c c6 45 d3 46 c6 45 d4 75 c6 45 d5 55 c6 45 d6 70 c6 45 d7 67 c6 45 d8 72 c6 45 d9 61 c6 45 da 64 c6 45 db 72 c6 45 dc 73 } //1
		$a_01_1 = {c6 45 f0 47 c6 45 f1 65 c6 45 f2 74 c6 45 f3 6f c6 45 f4 6e c6 45 f5 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}