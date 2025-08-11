
rule Trojan_BAT_LummaStealer_AZVA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AZVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 07 03 07 91 07 04 28 ?? ?? 00 06 9c 07 17 d6 0b 00 07 05 fe 02 16 fe 01 0c 08 2d e3 } //5
		$a_03_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? ?? 00 06 28 ?? ?? 00 0a 0a 2b 00 06 2a } //2
		$a_03_2 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=9
 
}