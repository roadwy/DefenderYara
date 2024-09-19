
rule Trojan_Win32_Fragtor_ASGH_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 69 73 67 69 73 6a 68 67 68 41 73 72 67 75 69 65 72 } //2 NoisgisjhghAsrguier
		$a_01_1 = {4f 6a 61 73 67 75 69 73 65 69 67 75 68 73 68 67 } //2 Ojasguiseiguhshg
		$a_01_2 = {4f 73 67 68 75 73 67 68 75 75 68 41 69 75 73 67 68 73 65 75 72 67 } //2 OsghusghuuhAiusghseurg
		$a_01_3 = {4b 69 73 61 6a 67 66 6f 69 73 6a 67 6a 73 61 66 } //2 Kisajgfoisjgjsaf
		$a_01_4 = {54 6f 69 61 67 73 66 6f 69 73 61 64 6f 69 41 6f 69 73 67 6a 69 } //2 ToiagsfoisadoiAoisgji
		$a_01_5 = {56 73 67 69 6f 65 73 61 6a 67 69 73 61 75 65 68 67 } //2 Vsgioesajgisauehg
		$a_01_6 = {4a 69 73 61 68 67 66 69 75 73 65 61 68 41 73 67 68 75 69 68 73 65 } //2 JisahgfiuseahAsghuihse
		$a_01_7 = {4d 6f 61 73 67 66 69 75 65 61 68 41 73 72 69 67 75 68 72 73 75 68 } //2 MoasgfiueahAsriguhrsuh
		$a_01_8 = {52 6f 61 73 75 65 68 67 66 61 75 69 33 44 } //2 Roasuehgfaui3D
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=6
 
}