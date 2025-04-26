
rule Trojan_WinNT_Sirefef_gen_B{
	meta:
		description = "Trojan:WinNT/Sirefef.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c } //1 KeGetCurrentIrql
		$a_00_1 = {50 72 6f 62 65 46 6f 72 52 65 61 64 } //1 ProbeForRead
		$a_00_2 = {3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e } //1 :\vc5\release\kinject.
		$a_00_3 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 5c 00 25 00 30 00 38 00 58 00 2e 00 64 00 6c 00 6c 00 } //1 \\?\globalroot\Device\__max++>\%08X.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_WinNT_Sirefef_gen_B_2{
	meta:
		description = "Trojan:WinNT/Sirefef.gen!B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 47 65 74 43 75 72 72 65 6e 74 49 72 71 6c } //1 KeGetCurrentIrql
		$a_01_1 = {50 72 6f 62 65 46 6f 72 52 65 61 64 } //1 ProbeForRead
		$a_01_2 = {3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e } //1 :\vc5\release\kinject.
		$a_01_3 = {5c 00 5c 00 3f 00 5c 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 72 00 6f 00 6f 00 74 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 3e 00 5c 00 25 00 30 00 38 00 58 00 2e 00 64 00 6c 00 6c 00 } //1 \\?\globalroot\Device\__max++>\%08X.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}