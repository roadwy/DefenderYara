
rule Backdoor_Win32_Ixeshe_F_dha{
	meta:
		description = "Backdoor:Win32/Ixeshe.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 57 c6 85 90 01 04 32 c6 85 90 01 04 31 c6 85 90 01 05 c6 85 90 01 04 2e 90 00 } //1
		$a_02_1 = {ff 2f c6 85 90 01 04 79 c6 85 90 01 04 6d c6 85 90 01 04 2f c6 85 90 01 04 41 c6 85 90 01 04 74 c6 85 90 01 04 74 90 00 } //1
		$a_00_2 = {54 c6 85 99 ef ff ff 44 c6 85 9a ef ff ff 4f c6 85 9b ef ff ff 57 c6 85 9c ef ff ff 4e c6 85 9d ef ff ff 0d c6 85 9e ef ff ff 0a } //1
		$a_00_3 = {6b c6 85 45 ef ff ff 4b c6 85 46 ef ff ff 49 c6 85 47 ef ff ff 4c c6 85 48 ef ff ff 4c c6 85 49 ef ff ff 20 c6 85 4a ef ff ff 25 c6 85 4b ef ff ff 73 c6 85 4c ef ff ff 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}