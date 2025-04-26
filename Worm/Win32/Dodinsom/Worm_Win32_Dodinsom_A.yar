
rule Worm_Win32_Dodinsom_A{
	meta:
		description = "Worm:Win32/Dodinsom.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f5 2e 00 00 00 04 a4 fe 0a ?? 00 08 00 04 ?? fe fb ef ?? fe f5 73 00 00 00 04 ?? fe 0a ?? 00 08 00 04 ?? fe fb ef ?? fe f5 77 00 00 00 04 ?? fe 0a ?? 00 08 00 04 ?? fe fb ef ?? fe f5 66 00 00 } //1
		$a_03_1 = {f4 14 eb 6e ?? ff b3 f4 01 eb ab fb e6 fb ff } //1
		$a_01_2 = {f5 01 00 00 00 c5 f5 02 00 00 00 c5 f5 04 00 00 00 c5 f5 20 00 00 00 c5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}