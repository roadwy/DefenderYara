
rule TrojanDropper_Win32_Dapato_V_MTB{
	meta:
		description = "TrojanDropper:Win32/Dapato.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b d6 6a 08 c1 e2 ?? 59 f7 c2 00 00 00 80 74 ?? 03 d2 81 f2 b7 1d c1 04 eb ?? d1 e2 49 75 ?? 89 17 46 83 c7 ?? 81 fe 00 01 00 00 7c } //1
		$a_00_1 = {64 65 66 65 6e 64 65 72 5f 64 65 6c 65 74 65 } //1 defender_delete
		$a_00_2 = {53 65 72 76 69 63 65 41 70 70 2e 65 78 65 } //1 ServiceApp.exe
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}