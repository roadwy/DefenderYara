
rule Worm_Win32_Tespot_A{
	meta:
		description = "Worm:Win32/Tespot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 :\autorun.inf
		$a_01_1 = {5b 2e 53 68 65 6c 6c 43 6c 61 73 73 49 6e 66 6f 5d } //1 [.ShellClassInfo]
		$a_03_2 = {3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1
		$a_03_3 = {3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 73 70 6f 6f 6c 73 76 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}