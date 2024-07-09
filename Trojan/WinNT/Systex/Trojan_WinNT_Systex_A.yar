
rule Trojan_WinNT_Systex_A{
	meta:
		description = "Trojan:WinNT/Systex.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {9c 60 b9 76 01 00 00 0f 32 a3 ?? ?? ?? ?? 61 9d 83 3d ?? ?? ?? ?? 06 73 ?? bb ?? ?? ?? ?? c7 45 fc 09 00 00 00 } //1
		$a_02_1 = {83 f8 02 75 ?? c7 05 ?? ?? ?? ?? 21 02 00 00 c3 83 f8 01 75 0b c7 05 ?? ?? ?? ?? 25 02 00 00 c3 85 c0 75 33 c7 05 ?? ?? ?? ?? 12 02 00 00 c3 83 f8 06 } //1
		$a_00_2 = {53 4f 47 4f 55 45 58 50 4c 4f 52 45 52 2e 45 58 45 } //1 SOGOUEXPLORER.EXE
		$a_00_3 = {47 52 45 45 4e 42 52 4f 57 53 45 52 2e 45 58 45 } //1 GREENBROWSER.EXE
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}