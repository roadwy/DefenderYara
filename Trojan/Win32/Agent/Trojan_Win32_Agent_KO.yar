
rule Trojan_Win32_Agent_KO{
	meta:
		description = "Trojan:Win32/Agent.KO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 76 50 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 89 ?? fc fc 56 8b 4e 54 8b 75 08 8b ?? fc 33 c0 f3 a4 5e } //1
		$a_03_1 = {51 b9 b6 dc 0e 00 81 c1 1c 02 00 00 8b 45 d4 d1 c0 c1 c8 ?? 85 c0 c1 c0 ?? 50 8f 45 d4 } //1
		$a_03_2 = {68 00 00 cf 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 cc 6a 00 ff 75 cc e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}