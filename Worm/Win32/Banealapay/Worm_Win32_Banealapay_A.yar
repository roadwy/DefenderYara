
rule Worm_Win32_Banealapay_A{
	meta:
		description = "Worm:Win32/Banealapay.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 6e 66 65 63 74 44 72 69 76 65 } //1 InfectDrive
		$a_00_1 = {47 65 74 41 6c 69 76 65 48 6f 73 74 73 } //1 GetAliveHosts
		$a_00_2 = {49 6e 66 65 63 74 53 75 62 6e 65 74 } //1 InfectSubnet
		$a_02_3 = {49 00 6e 00 69 00 63 00 69 00 6f 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 49 00 6e 00 69 00 63 00 69 00 6f 00 [0-20] 63 00 6f 00 70 00 79 00 [0-20] 5c 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1
		$a_03_4 = {66 05 01 00 66 89 45 ?? e9 ?? ?? ff ff } //1
		$a_03_5 = {66 2d 11 00 0f bf c0 50 8d 45 ?? 50 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}