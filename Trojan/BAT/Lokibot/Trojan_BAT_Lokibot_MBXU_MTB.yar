
rule Trojan_BAT_Lokibot_MBXU_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 00 69 00 61 00 75 00 54 00 4d 00 2e 00 43 00 53 00 68 00 61 00 72 00 70 00 2e 00 54 00 69 00 6b 00 69 00 52 00 6f 00 75 00 74 00 65 00 72 00 } //4 GiauTM.CSharp.TikiRouter
		$a_01_1 = {41 72 76 6f 72 65 } //3 Arvore
		$a_01_2 = {53 70 6c 69 74 } //2 Split
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}