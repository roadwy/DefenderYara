
rule Trojan_Win32_Slepak_DEA_MTB{
	meta:
		description = "Trojan:Win32/Slepak.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f0 8a 44 24 14 2b f5 c0 e3 06 81 ee 11 d7 00 00 2a c3 8a d8 89 2d ?? ?? ?? ?? 88 1d } //1
		$a_00_1 = {04 37 02 d8 8a c1 b1 34 f6 e9 8a ca f6 d9 2a c8 0f b7 45 fc 02 d9 8d 0c 30 81 f9 a8 00 00 00 75 1e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}