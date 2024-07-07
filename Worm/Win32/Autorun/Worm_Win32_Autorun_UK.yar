
rule Worm_Win32_Autorun_UK{
	meta:
		description = "Worm:Win32/Autorun.UK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 3a 57 e8 90 01 04 83 e8 02 74 17 83 e8 02 74 1f 83 e8 02 75 25 90 00 } //1
		$a_03_1 = {ba 07 00 00 00 8b 45 f8 e8 90 01 04 8d 85 90 01 04 b9 90 01 04 8b 55 fc e8 90 01 04 8b 85 90 01 04 e8 90 01 04 84 c0 74 3e 90 00 } //1
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d 00 } //1 䅛瑵副湵]
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}