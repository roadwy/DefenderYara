
rule Trojan_BAT_Redline_GBK_MTB{
	meta:
		description = "Trojan:BAT/Redline.GBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 62 71 40 72 6f 6f 62 6b 71 4d 6f 6c 60 62 70 70 } //Dbq@roobkqMol`bpp  1
		$a_80_1 = {51 4b 58 54 4b 52 70 6f 6c 4a 52 52 } //QKXTKRpolJRR  1
		$a_80_2 = {37 49 52 54 55 41 4c 78 4c 4c 4f 43 24 58 2e 55 } //7IRTUALxLLOC$X.U  1
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {68 79 72 61 74 65 44 79 65 72 } //1 hyrateDyer
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}