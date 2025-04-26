
rule Trojan_Win32_Laplas_PA_MTB{
	meta:
		description = "Trojan:Win32/Laplas.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 89 44 24 1c 8b 44 24 20 01 44 24 1c 8b 4c 24 14 8b c6 d3 e8 8b 4c 24 30 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 24 8d 44 24 24 e8 ?? ?? ?? ?? 8b 44 24 1c 31 44 24 10 81 3d dc 8b b9 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}