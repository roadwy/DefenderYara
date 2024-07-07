
rule TrojanProxy_Win32_Hioles_A{
	meta:
		description = "TrojanProxy:Win32/Hioles.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 75 10 ff 75 0c ff d7 3b c6 7e 90 01 01 39 75 14 74 15 8b 4d 10 8b 09 81 f9 47 45 54 20 74 90 01 01 81 f9 50 4f 53 54 74 90 01 01 56 50 ff 75 10 ff 75 08 ff 15 90 00 } //1
		$a_03_1 = {6a 16 50 ff 74 24 14 c7 00 90 01 04 c7 40 04 90 01 04 c6 40 08 90 01 01 ff 15 90 01 04 83 f8 16 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}