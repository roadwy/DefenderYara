
rule VirTool_Win32_CryptInject_L{
	meta:
		description = "VirTool:Win32/CryptInject.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 64 66 5f 72 65 61 64 65 72 2e 63 72 74 } //01 00 
		$a_01_1 = {73 71 6c 6c 69 74 65 2e 64 6c 6c } //01 00 
		$a_01_2 = {5c 6d 2e 64 6c 6c } //01 00 
		$a_01_3 = {5c 61 61 70 2e 70 70 6b } //01 00 
		$a_01_4 = {5c 70 64 66 2e 65 78 65 } //01 00 
		$a_01_5 = {65 00 6b 00 72 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_6 = {65 00 67 00 75 00 69 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}