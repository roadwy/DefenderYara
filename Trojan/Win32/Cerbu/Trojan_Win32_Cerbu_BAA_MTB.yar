
rule Trojan_Win32_Cerbu_BAA_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 00 83 c0 01 89 45 00 8b 4d 50 0f b7 51 06 39 55 00 0f 8c } //2
		$a_01_1 = {6b 45 00 28 03 45 60 b9 01 00 00 00 c1 e1 00 8a 14 08 88 55 33 0f be 45 33 83 f8 72 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}