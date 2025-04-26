
rule Ransom_Win32_Basta_AC{
	meta:
		description = "Ransom:Win32/Basta.AC,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {56 6a 00 6a 00 8b f1 56 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 89 46 0c 5e c3 } //10
		$a_03_2 = {51 6a 10 e8 ?? ?? ?? ?? 83 c4 04 89 45 ?? [0-07] 85 c0 74 ?? 8b 4d 08 89 48 08 8b 4d 0c 89 48 04 8b 4d 10 89 08 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=21
 
}