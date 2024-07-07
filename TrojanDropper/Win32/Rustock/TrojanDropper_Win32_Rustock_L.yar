
rule TrojanDropper_Win32_Rustock_L{
	meta:
		description = "TrojanDropper:Win32/Rustock.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 7e 04 03 75 1b 8b 46 18 38 18 75 14 8b 46 0c 38 18 74 0d ff 75 f0 50 ff 55 08 } //1
		$a_03_1 = {3b fe 89 7d f8 0f 82 90 01 02 00 00 6a 04 68 00 30 00 00 56 53 e8 90 01 04 3b c3 89 45 f0 90 09 05 00 be 90 03 02 02 00 2e c0 36 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}