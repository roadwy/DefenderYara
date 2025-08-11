
rule Trojan_Win32_Zbot_BAH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 5a c1 c2 0a c1 ca 02 c7 01 ?? ?? ?? ?? 31 01 83 c1 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zbot_BAH_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ee 02 8d 76 01 29 de 31 db 4b 21 f3 c7 42 ?? ?? ?? ?? ?? 31 32 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zbot_BAH_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ec c7 05 [0-04] 7e d2 4a 50 c7 05 [0-04] 61 00 00 00 c7 05 [0-04] e6 ff be 09 c7 05 [0-04] 62 00 00 00 c7 05 [0-04] a0 f0 76 e0 c7 05 [0-04] 63 00 00 00 c7 05 [0-04] 3e a2 aa ac c7 05 [0-04] 64 00 00 00 c7 05 [0-04] ca f3 a2 81 } //2
		$a_01_1 = {68 3e a2 aa ac 68 7e d2 4a 50 68 ca f3 a2 81 68 88 98 8a 59 68 8e d7 be 43 68 00 3a b4 93 68 40 49 5a fd 68 66 3d 7e 05 68 ca f3 a2 81 68 88 98 8a 59 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}