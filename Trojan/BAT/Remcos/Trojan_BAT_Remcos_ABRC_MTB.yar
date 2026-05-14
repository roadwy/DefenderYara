
rule Trojan_BAT_Remcos_ABRC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 01 28 ?? ?? ?? ?? 9c 25 17 0f 01 28 ?? ?? ?? ?? 9c 25 18 0f 01 28 ?? ?? ?? ?? 9c 02 7b ?? 00 00 04 25 2d 16 26 02 02 } //4
		$a_80_1 = {47 65 74 50 69 78 65 6c } //GetPixel  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}