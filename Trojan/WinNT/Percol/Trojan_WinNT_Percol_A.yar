
rule Trojan_WinNT_Percol_A{
	meta:
		description = "Trojan:WinNT/Percol.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 8b 45 08 c7 40 40 ?? ?? ?? ?? 8b 4d 08 8b 55 08 8b 42 40 89 41 38 8b 4d 08 c7 41 70 ?? ?? ?? ?? 8b 55 08 c7 42 34 ?? ?? ?? ?? 33 c0 8b 4d fc 33 cd } //1
		$a_02_1 = {66 c7 45 ee 63 00 66 c7 45 f0 4c 00 66 c7 45 f2 69 00 66 c7 45 f4 6e 00 66 c7 45 f6 6b 00 66 c7 45 f8 00 00 6a 2a 8d 45 d0 50 e8 ?? ?? ?? ?? 89 45 c8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 55 c8 89 45 c4 83 7d c4 00 7d ?? 8b 4d cc 51 } //1
		$a_01_2 = {c7 85 30 ff ff ff 74 fa 4c 16 c7 85 34 ff ff ff 4a 0a 47 45 c7 85 38 ff ff ff 0d a5 ed 4f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}