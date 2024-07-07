
rule Worm_Win32_Autorun_AGK{
	meta:
		description = "Worm:Win32/Autorun.AGK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 7d f0 05 7f 90 01 01 8b 45 f0 8b 44 85 c8 89 44 24 04 8b 45 f4 8b 44 85 c8 89 04 24 e8 90 01 04 8d 45 f0 ff 00 eb 90 00 } //2
		$a_00_1 = {6f 70 65 6e 3d 22 53 56 43 48 4f 53 54 2e 63 6f 6d 20 2f 73 } //1 open="SVCHOST.com /s
		$a_00_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_00_3 = {44 45 53 54 4f 52 59 5f 5a 5a 5f 25 64 } //1 DESTORY_ZZ_%d
		$a_00_4 = {77 6a 76 69 65 77 33 32 2e 63 6f 6d 20 2f 73 } //1 wjview32.com /s
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}