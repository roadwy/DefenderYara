
rule TrojanProxy_Win32_Sefbov_B{
	meta:
		description = "TrojanProxy:Win32/Sefbov.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 18 c6 45 f5 5a } //1
		$a_03_1 = {68 28 0a 00 00 a3 08 90 01 01 90 03 02 02 40 00 00 10 90 00 } //1
		$a_01_2 = {38 39 2e 31 30 37 2e 31 30 34 } //1 89.107.104
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}