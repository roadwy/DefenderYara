
rule Backdoor_WinNT_Blazgel_A{
	meta:
		description = "Backdoor:WinNT/Blazgel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7d fc 93 08 00 00 75 41 c7 05 ?? ?? ?? ?? a0 00 00 00 c7 05 ?? ?? ?? ?? 58 01 00 00 c7 05 ?? ?? ?? ?? 70 02 00 00 c7 05 ?? ?? ?? ?? 40 02 00 00 c7 05 ?? ?? ?? ?? 9c 00 00 00 c7 05 ?? ?? ?? ?? b0 01 00 00 e9 ?? 00 00 00 81 7d fc 28 0a 00 00 75 34 } //1
		$a_01_1 = {74 43 8b 45 fc 66 8b 00 8b d8 66 81 e3 00 f0 66 81 fb 00 30 75 1e 25 ff 0f 00 00 ff 45 f4 03 01 8b 1c 30 2b 5f 1c 3b 5d 0c 75 09 66 81 7c 30 fe c7 05 74 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}