
rule Trojan_Win32_Rafoti_C_dll{
	meta:
		description = "Trojan:Win32/Rafoti.C!dll,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {74 22 c6 45 ?? 64 c6 45 ?? 6d c6 45 ?? 73 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 76 c6 45 ?? 65 c6 45 ?? 72 eb 14 c6 45 ?? 72 c6 45 ?? 70 c6 45 ?? 63 c6 45 ?? 73 c6 45 ?? 73 33 c0 } //10
		$a_00_1 = {00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //1
		$a_00_2 = {00 32 30 30 00 68 74 74 70 3a 2f 2f 25 73 3a 39 30 30 31 2f 25 64 25 73 30 30 } //1 ㈀〰栀瑴㩰⼯猥㤺〰⼱搥猥〰
		$a_00_3 = {00 48 54 54 50 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 73 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}