
rule Trojan_Win32_Doina_BD_MTB{
	meta:
		description = "Trojan:Win32/Doina.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 a1 a4 76 f2 fd ef 4f ae 07 50 d3 13 d2 08 69 fe 78 92 ae c7 51 e5 4a b5 3d 5f 96 3f 88 24 eb 19 c1 3e c5 2f 74 7e 4d a7 76 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}