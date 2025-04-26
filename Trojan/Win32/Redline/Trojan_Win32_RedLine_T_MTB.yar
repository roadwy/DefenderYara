
rule Trojan_Win32_RedLine_T_MTB{
	meta:
		description = "Trojan:Win32/RedLine.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {29 f9 29 ce 81 c1 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c1 e9 02 f3 a5 89 de 83 c3 01 c7 04 24 00 e0 52 00 89 5c 24 04 83 e6 03 e8 ?? ?? ?? ?? 0f b6 86 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 81 fb 00 ac 01 00 75 d3 } //10
		$a_01_1 = {89 c2 83 e2 03 0f b6 92 20 c4 52 00 30 90 20 18 51 00 83 c0 01 3d 00 ac 01 00 } //10
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}