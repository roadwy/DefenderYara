
rule Trojan_Win32_CobalStrike_ATZ_MTB{
	meta:
		description = "Trojan:Win32/CobalStrike.ATZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 02 8d ?? ?? 03 c9 2b c1 8a 44 05 f8 30 84 35 c4 a8 fa ff 46 3b f7 } //1
		$a_00_1 = {8b 7d f8 33 f6 c7 45 f8 71 61 78 7a 66 c7 45 fc 6e 62 } //1
		$a_00_2 = {6a 40 68 00 30 00 00 57 6a 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}