
rule Ransom_Win32_Basta_YAA_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c5 04 8b 82 9c 00 00 00 2d ?? ?? ?? ?? 31 87 dc 00 00 00 8b 87 94 00 00 00 83 e8 53 09 87 84 00 00 00 8b 47 4c 33 c1 83 e8 11 } //1
		$a_01_1 = {88 14 01 8b cb ff 47 3c 8b 57 3c 8b 47 60 c1 e9 08 88 0c 02 ff 47 3c 8b 4f 3c 8b 47 60 88 1c 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}