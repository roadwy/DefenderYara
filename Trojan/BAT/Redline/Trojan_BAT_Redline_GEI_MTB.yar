
rule Trojan_BAT_Redline_GEI_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 45 00 00 70 72 19 00 00 70 14 28 ?? ?? ?? 0a 18 8d 1c 00 00 01 25 16 d0 ?? ?? ?? ?? 28 ?? ?? ?? 0a a2 25 17 d0 ?? ?? ?? ?? 28 ?? ?? ?? 0a a2 28 } //10
		$a_80_1 = {47 65 74 4d 65 74 78 68 6f 64 } //GetMetxhod  1
		$a_80_2 = {49 6e 76 78 6f 6b 65 } //Invxoke  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}