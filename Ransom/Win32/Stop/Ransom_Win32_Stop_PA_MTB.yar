
rule Ransom_Win32_Stop_PA_MTB{
	meta:
		description = "Ransom:Win32/Stop.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 45 ?? 33 c3 33 c6 29 45 ?? ff 4d ?? 0f 85 } //1
		$a_03_1 = {8b de c1 e3 ?? 03 5d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
		$a_03_2 = {88 04 0f 89 75 ?? c1 e8 ?? 81 6d ?? ?? ?? ?? ?? 8b 45 ?? a3 ?? ?? ?? ?? 8a 45 fe 88 44 0f 01 8a 45 ff 88 44 0f 02 83 c7 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}