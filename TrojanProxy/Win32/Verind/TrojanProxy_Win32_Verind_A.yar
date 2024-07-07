
rule TrojanProxy_Win32_Verind_A{
	meta:
		description = "TrojanProxy:Win32/Verind.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 e2 ea c7 03 2e 65 78 65 c6 43 04 00 } //1
		$a_01_1 = {83 f8 04 74 09 b8 ff 00 00 00 c9 } //1
		$a_03_2 = {67 e3 0b 8b f0 ad 31 05 90 01 04 e2 f7 5e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}