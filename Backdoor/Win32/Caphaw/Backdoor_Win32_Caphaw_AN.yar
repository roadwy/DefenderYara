
rule Backdoor_Win32_Caphaw_AN{
	meta:
		description = "Backdoor:Win32/Caphaw.AN,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 04 00 00 "
		
	strings :
		$a_03_0 = {db 44 24 08 dc 05 ?? ?? ?? ?? e8 ?? ?? 00 00 99 [0-1f] 89 ?? 24 04 8b ?? 24 (41|42) 89 ?? 24 81 3c 24 ?? ?? ?? ?? 72 } //1
		$a_03_1 = {8b 46 3c 8b 4c ?? 54 8b d1 } //100
		$a_03_2 = {8b 4e 3c 8b 4c ?? 54 8b d1 } //100
		$a_01_3 = {8b 43 3c 8b 4c 18 54 8b d1 } //100
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_01_3  & 1)*100) >=101
 
}