
rule Backdoor_Win32_Xtrat_D{
	meta:
		description = "Backdoor:Win32/Xtrat.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {58 00 74 00 72 00 65 00 6d 00 65 00 20 00 52 00 41 00 54 00 } //1 Xtreme RAT
		$a_00_1 = {43 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 58 00 74 00 72 00 65 00 6d 00 65 00 52 00 41 00 54 00 } //1 COFTWARE\XtremeRAT
		$a_00_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 } //1 Windows NT\CurrentVersion\Winlogon
		$a_03_3 = {8b 12 83 ea 1e a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}