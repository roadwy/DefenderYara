
rule Trojan_Win32_Fragtor_GXY_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 75 69 61 73 66 75 69 73 61 41 69 61 75 67 68 61 69 75 65 68 67 } //1 FuiasfuisaAiaughaiuehg
		$a_01_1 = {54 61 73 69 75 66 67 61 73 69 75 67 41 69 61 68 67 66 69 61 75 68 65 67 } //1 TasiufgasiugAiahgfiauheg
		$a_80_2 = {4b 69 73 73 20 74 6f 20 68 33 72 20 70 33 33 7a 79 20 61 24 24 } //Kiss to h3r p33zy a$$  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}