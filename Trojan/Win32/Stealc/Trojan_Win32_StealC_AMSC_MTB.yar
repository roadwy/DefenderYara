
rule Trojan_Win32_StealC_AMSC_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 36 32 2e 36 30 2e 32 32 36 2e 31 35 39 2f [0-0f] 2e 65 78 65 } //5
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 6f 70 65 6e 3d 55 70 64 61 74 65 2e 65 78 65 0d 0a 69 63 6f 6e 3d 73 68 65 6c 6c 33 32 2e 64 6c 6c } //1
		$a_80_2 = {31 44 58 63 31 65 61 7a 79 57 54 48 54 71 36 4a 4d 64 55 52 53 71 71 72 46 47 54 7a 47 4c 38 65 46 31 } //1DXc1eazyWTHTq6JMdURSqqrFGTzGL8eF1  1
		$a_80_3 = {4c 65 64 78 4b 42 57 46 34 4d 69 4d 33 78 39 46 37 7a 6d 43 64 61 78 6e 6e 75 38 41 38 53 55 6f 68 5a } //LedxKBWF4MiM3x9F7zmCdaxnnu8A8SUohZ  1
		$a_80_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //GetClipboardData  1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}