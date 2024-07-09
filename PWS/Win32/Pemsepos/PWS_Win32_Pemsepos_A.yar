
rule PWS_Win32_Pemsepos_A{
	meta:
		description = "PWS:Win32/Pemsepos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 e0 8b 7d 0c 3b c7 73 10 8b 4d 08 0f b6 14 08 83 f2 ?? 88 14 08 40 eb e6 } //1
		$a_01_1 = {0f b7 44 24 28 03 44 24 40 03 44 24 3c c1 e0 12 33 44 24 10 31 44 24 04 b8 06 00 00 80 0f a2 31 4c 24 04 8b 44 24 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}