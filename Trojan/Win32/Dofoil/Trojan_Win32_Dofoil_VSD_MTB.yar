
rule Trojan_Win32_Dofoil_VSD_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.VSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {23 c7 81 3d ?? ?? ?? ?? 21 06 00 00 a3 ?? ?? ?? ?? 75 90 09 12 00 a1 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 03 05 } //1
		$a_02_1 = {30 04 37 4e 79 90 09 05 00 e8 } //1
		$a_02_2 = {8b f5 c1 ee 05 03 74 24 34 33 c7 81 3d ?? ?? ?? ?? b4 11 00 00 89 44 24 10 75 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}