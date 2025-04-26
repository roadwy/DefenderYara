
rule Trojan_Win32_Nymaim_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 69 73 2d 4a 42 4e 30 4b 2e 74 6d 70 5c 69 73 2d 4e 39 47 30 42 2e 74 6d 70 } //5 C:\TEMP\is-JBN0K.tmp\is-N9G0B.tmp
		$a_01_1 = {47 54 53 65 61 72 63 68 65 72 } //4 GTSearcher
		$a_01_2 = {31 2e 33 2e 32 2e 38 34 } //4 1.3.2.84
		$a_01_3 = {6c 73 64 73 65 6d 69 68 69 64 64 65 6e 30 } //3 lsdsemihidden0
		$a_01_4 = {4d 00 6f 00 6a 00 61 00 20 00 67 00 6c 00 61 00 73 00 62 00 61 00 } //3 Moja glasba
		$a_01_5 = {53 70 61 77 6e 69 6e 67 20 5f 52 65 67 44 4c 4c 2e 74 6d 70 } //2 Spawning _RegDLL.tmp
		$a_01_6 = {49 73 50 6f 77 65 72 55 73 65 72 4c 6f 67 67 65 64 4f 6e } //1 IsPowerUserLoggedOn
		$a_01_7 = {72 65 67 73 76 72 33 32 2e 65 78 65 } //1 regsvr32.exe
		$a_01_8 = {49 6e 6e 6f 20 53 65 74 75 70 } //1 Inno Setup
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=24
 
}