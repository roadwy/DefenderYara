
rule Backdoor_Win32_Zegost_C_dll{
	meta:
		description = "Backdoor:Win32/Zegost.C!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 80 34 11 19 41 3b c8 7c e5 } //2
		$a_03_1 = {8d 8e b0 00 00 00 c6 44 24 ?? 47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73 } //2
		$a_00_2 = {47 6c 6f 62 61 6c 5c 54 6f 72 72 65 6e 74 20 25 64 } //1 Global\Torrent %d
		$a_00_3 = {46 75 63 6b 5f 6b 61 76 5f 72 69 73 69 6e 67 } //1 Fuck_kav_rising
		$a_00_4 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29 } //1 RegQueryValueEx(Svchost\netsvcs)
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}