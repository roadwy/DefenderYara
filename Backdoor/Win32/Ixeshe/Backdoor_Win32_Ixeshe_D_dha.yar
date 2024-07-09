
rule Backdoor_Win32_Ixeshe_D_dha{
	meta:
		description = "Backdoor:Win32/Ixeshe.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2f c6 44 24 ?? 41 c6 44 24 ?? 4c c6 44 24 ?? 49 c6 44 24 ?? 56 c6 44 24 ?? 45 } //1
		$a_03_1 = {80 c2 41 50 c6 44 24 ?? 52 c6 44 24 ?? 45 c6 44 24 ?? 4d c6 44 24 ?? 4f } //1
		$a_03_2 = {b9 08 00 00 00 b8 cc cc cc cc 8d [0-06] 6a 00 f3 ab } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}