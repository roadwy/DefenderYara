
rule Trojan_Win32_ShellLoader_SX_MTB{
	meta:
		description = "Trojan:Win32/ShellLoader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 1c b8 03 de 8b f2 8a 0b 6b f6 7f 0f be c1 03 f0 43 84 c9 75 f1 8b 5d f4 89 75 f0 8b 75 f8 3b 5d f0 74 08 47 3b 7d ec 72 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ShellLoader_SX_MTB_2{
	meta:
		description = "Trojan:Win32/ShellLoader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 03 4d fc 0f be 51 01 0f be 45 0c 33 d0 c1 e2 08 8b 4d 08 03 4d fc 0f be 01 0f be 4d 0c 33 c1 0b d0 } //20
		$a_01_1 = {c7 45 b0 05 40 00 80 c6 45 bb a2 c6 45 bc e1 c6 45 bd a2 c6 45 be 98 c6 45 bf a2 c6 45 c0 fe c6 45 c1 a2 c6 45 c2 f2 c6 45 c3 a2 c6 45 c4 d0 c6 45 c5 a2 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}