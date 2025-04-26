
rule Trojan_Win32_Lowzones_GU{
	meta:
		description = "Trojan:Win32/Lowzones.GU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {b3 01 8b c7 e8 ?? ?? ?? ff 8b f3 81 e6 ff 00 00 00 8b 55 fc 8a 54 32 ff [0-03] 88 54 30 ff 43 fe 4d fb 75 ?? 33 c0 5a 59 59 64 89 10 } //1
		$a_03_1 = {c6 45 f7 01 8b 45 f8 e8 ?? ?? ?? ff 33 d2 8a 55 f7 33 c9 8a 4d f7 8b 5d fc 8a 4c 0b ff [0-03] 88 4c 10 ff fe 45 f7 fe 4d f6 75 ?? 33 c0 5a 59 59 64 89 10 } //1
		$a_03_2 = {6a 00 6a 00 6a 02 6a 01 8b 0d ?? ?? 42 00 8b 09 b2 01 a1 ?? ?? 42 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}