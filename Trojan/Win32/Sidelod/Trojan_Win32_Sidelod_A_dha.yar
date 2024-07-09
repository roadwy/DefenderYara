
rule Trojan_Win32_Sidelod_A_dha{
	meta:
		description = "Trojan:Win32/Sidelod.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff d6 8b 45 f4 8a 0c ?? ff 05 ?? ?? ?? ?? [0-08] 2a cb [0-08] 80 f1 3f 6a 00 02 cb [0-05] 88 0f ff d6 47 ff 4d fc 75 } //2
		$a_03_1 = {6a 40 6a 10 57 ff ?? 85 c0 [0-14] ff d6 [0-0a] bb ?? ?? ?? ?? 2b df 6a 00 83 eb 05 6a 00 89 5d fc } //2
		$a_01_2 = {6a 00 6a 00 c6 07 e9 ff d6 } //1
		$a_03_3 = {51 68 19 00 02 00 6a 00 6a 10 68 ?? ?? ?? ?? b3 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}