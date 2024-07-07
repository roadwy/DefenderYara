
rule Trojan_Win32_Raccoon_RL_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 01 e1 34 ef c6 c3 } //1
		$a_03_1 = {ee 3d ea f4 90 02 10 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 81 3d 90 01 04 6e 0c 00 00 90 02 60 81 6d 90 01 01 36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 4d 90 01 01 8b d6 d3 e2 90 02 25 8b c6 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 33 4d 90 02 08 31 4d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}