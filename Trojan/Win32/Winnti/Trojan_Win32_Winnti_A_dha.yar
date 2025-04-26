
rule Trojan_Win32_Winnti_A_dha{
	meta:
		description = "Trojan:Win32/Winnti.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8a 11 3a 10 75 ?? 84 d2 74 ?? 8a 51 01 3a 50 01 75 ?? 83 c1 02 83 c0 02 84 d2 75 ?? 33 c0 eb ?? 1b c0 83 d8 ff 85 c0 74 ?? 43 83 c6 04 } //1
		$a_01_1 = {00 52 53 44 53 } //1
		$a_00_2 = {6e 65 74 73 76 63 73 } //1 netsvcs
		$a_00_3 = {53 65 74 41 70 70 49 6e 69 74 44 6c 6c 44 61 74 61 49 6e 66 } //1 SetAppInitDllDataInf
		$a_00_4 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 \svchost.exe
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}