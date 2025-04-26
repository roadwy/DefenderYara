
rule Trojan_BAT_Mamut_NK_MTB{
	meta:
		description = "Trojan:BAT/Mamut.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 73 74 61 6b 61 53 6f 61 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 PustakaSoal.Resources.resources
		$a_01_1 = {41 6e 74 69 42 69 74 44 65 66 65 6e 64 65 72 } //2 AntiBitDefender
		$a_01_2 = {41 6e 74 69 41 76 61 73 74 } //2 AntiAvast
		$a_01_3 = {56 69 6e 64 65 78 65 72 2e 65 78 65 } //1 Vindexer.exe
		$a_01_4 = {61 64 64 4d 61 74 65 72 69 4b 68 75 73 75 73 55 53 42 } //1 addMateriKhususUSB
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}