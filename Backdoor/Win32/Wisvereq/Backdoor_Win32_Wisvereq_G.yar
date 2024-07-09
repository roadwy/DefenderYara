
rule Backdoor_Win32_Wisvereq_G{
	meta:
		description = "Backdoor:Win32/Wisvereq.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 00 } //1 〥堲┭㈰ⵘ〥堲┭㈰ⵘ〥堲┭㈰X
		$a_01_1 = {75 70 66 69 6c 65 00 00 63 6d 64 2e 65 78 65 00 } //1
		$a_03_2 = {61 62 00 00 25 [0-02] 64 [0-04] 6c 6f 61 64 66 69 6c 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}