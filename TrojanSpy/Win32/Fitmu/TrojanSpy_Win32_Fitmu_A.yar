
rule TrojanSpy_Win32_Fitmu_A{
	meta:
		description = "TrojanSpy:Win32/Fitmu.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 f8 15 74 28 83 f8 19 74 1c 83 f8 6e 74 10 } //1
		$a_01_1 = {74 08 41 83 f9 02 72 db eb 0a 8b 7c cc 14 46 83 fe 05 74 0f } //1
		$a_03_2 = {2b f0 8a 14 06 30 94 04 ?? ?? ?? ?? 40 3b c1 7c f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}