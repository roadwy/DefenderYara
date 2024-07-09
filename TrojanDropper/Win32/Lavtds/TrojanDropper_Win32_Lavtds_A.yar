
rule TrojanDropper_Win32_Lavtds_A{
	meta:
		description = "TrojanDropper:Win32/Lavtds.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c1 04 35 98 98 74 92 81 f9 c8 2c 00 00 89 84 2a ?? ?? ?? ?? 89 ca 75 e1 } //1
		$a_03_1 = {c1 27 72 66 ?? ?? ?? 41 30 29 18 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}