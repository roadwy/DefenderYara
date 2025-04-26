
rule Trojan_Win32_Delfinject_AC_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {57 6e 64 50 72 6f 63 50 74 72 25 2e 38 58 25 2e 38 58 } //WndProcPtr%.8X%.8X  3
		$a_80_1 = {76 63 6c 74 65 73 74 33 2e 64 6c 6c } //vcltest3.dll  3
		$a_80_2 = {42 4b 62 68 54 62 7e 58 42 4b 21 } //BKbhTb~XBK!  3
		$a_80_3 = {64 64 68 68 6c 6c 70 70 74 74 74 74 78 78 78 78 } //ddhhllppttttxxxx  3
		$a_80_4 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  3
		$a_80_5 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //WinHttpCrackUrl  3
		$a_80_6 = {44 65 6c 70 68 69 2e 52 75 } //Delphi.Ru  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}