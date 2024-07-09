
rule Trojan_Win32_Raccoon_RL_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 01 e1 34 ef c6 c3 } //1
		$a_03_1 = {ee 3d ea f4 [0-10] 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? 6e 0c 00 00 [0-60] 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 4d ?? 8b d6 d3 e2 [0-25] 8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 33 4d [0-08] 31 4d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}