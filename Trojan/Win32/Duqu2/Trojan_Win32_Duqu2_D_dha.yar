
rule Trojan_Win32_Duqu2_D_dha{
	meta:
		description = "Trojan:Win32/Duqu2.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 7b 00 33 00 37 00 38 00 37 00 44 00 45 00 41 00 46 00 2d 00 32 00 45 00 46 00 41 00 2d 00 42 00 44 00 43 00 41 00 2d 00 45 00 46 00 41 00 44 00 2d 00 31 00 37 00 32 00 45 00 44 00 33 00 35 00 41 00 42 00 43 00 44 00 34 00 7d 00 } //1 Global\{3787DEAF-2EFA-BDCA-EFAD-172ED35ABCD4}
		$a_03_1 = {8d 3a 8b 07 35 ?? ?? ?? ?? 0f c8 c1 c8 06 0f c8 89 03 83 c2 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}