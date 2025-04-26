
rule Trojan_Win32_Dridex_OX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {65 73 74 61 70 70 70 45 58 45 } //1 estapppEXE
		$a_81_1 = {51 44 64 65 66 61 75 6c 74 73 } //1 QDdefaults
		$a_81_2 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Oracle Corporation
		$a_81_3 = {6a 32 70 63 73 63 2e 64 6c 6c } //1 j2pcsc.dll
		$a_81_4 = {74 61 72 74 69 6e 67 50 6c 75 67 69 6e 5a 32 30 31 35 } //1 tartingPluginZ2015
		$a_81_5 = {48 65 32 47 6f 6f 67 6c 65 42 39 78 } //1 He2GoogleB9x
		$a_81_6 = {6e 75 6d 62 65 72 74 68 65 6d } //1 numberthem
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}