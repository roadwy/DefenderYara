
rule Ransom_Win32_Grymegat_A{
	meta:
		description = "Ransom:Win32/Grymegat.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 18 ff 2b c7 2b c3 33 c7 89 45 f4 8d 45 f0 8a 55 f4 } //1
		$a_03_1 = {68 22 02 00 00 50 e8 ?? ?? ?? ?? 6a 00 8b 03 8b 40 ?? 50 6a 07 50 e8 ?? ?? ?? ?? 6a 73 e8 ?? ?? ?? ?? 0f bf c0 f7 d8 83 c0 81 83 e8 02 } //1
		$a_03_2 = {68 2c 01 00 00 68 f4 01 00 00 e8 ?? ?? ?? ?? c3 } //1
		$a_03_3 = {68 89 13 00 00 8d 85 ?? ?? ff ff 50 53 e8 ?? ?? ?? ?? 6a 00 68 89 13 00 00 8d 85 ?? ?? ff ff 50 53 e8 } //1
		$a_01_4 = {26 53 74 61 74 75 73 3d 4c 6f 63 6b 26 74 65 78 74 3d } //1 &Status=Lock&text=
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}