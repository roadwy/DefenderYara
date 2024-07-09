
rule Worm_Win32_Cridex_L{
	meta:
		description = "Worm:Win32/Cridex.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 4b 00 42 00 25 00 30 00 38 00 75 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_03_1 = {8b 4d 0c 03 cb 51 ff 54 24 ?? 8b d0 85 d2 89 54 24 ?? 74 ?? 8b 75 00 8b 7d 10 8b 04 1e 03 f3 03 fb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}