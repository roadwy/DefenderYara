
rule Ransom_Win32_Basta_AC_MTB{
	meta:
		description = "Ransom:Win32/Basta.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 0c 02 83 c2 04 8b 0d ?? ?? ?? ?? 8b 81 a0 00 00 00 01 41 5c 8b 85 d0 00 00 00 8b 0d ?? ?? ?? ?? 2d ?? ?? ?? ?? 09 05 ?? ?? ?? ?? 8b 85 f4 00 00 00 35 ?? ?? ?? ?? 29 81 dc 00 00 00 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 85 dc 00 00 00 31 85 b0 00 00 00 81 fa 74 01 07 00 0f 8c } //4
		$a_00_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}