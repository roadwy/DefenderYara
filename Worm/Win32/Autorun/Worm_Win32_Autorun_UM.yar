
rule Worm_Win32_Autorun_UM{
	meta:
		description = "Worm:Win32/Autorun.UM,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {42 00 6c 00 34 00 63 00 6b 00 [0-04] 53 00 63 00 30 00 72 00 70 00 69 00 30 00 4e 00 } //1
		$a_00_1 = {7b 00 48 00 4f 00 4d 00 45 00 7d 00 } //1 {HOME}
		$a_00_2 = {7b 00 45 00 4e 00 44 00 7d 00 } //1 {END}
		$a_00_3 = {53 00 6f 00 6c 00 64 00 69 00 65 00 72 00 20 00 56 00 69 00 72 00 75 00 73 00 } //1 Soldier Virus
		$a_00_4 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_00_5 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 autorun.inf
		$a_00_6 = {54 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //1 Taskkill /im
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}