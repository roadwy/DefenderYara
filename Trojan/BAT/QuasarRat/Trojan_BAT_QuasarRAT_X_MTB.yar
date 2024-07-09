
rule Trojan_BAT_QuasarRAT_X_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 9c 06 17 d6 0a 11 ?? 17 d6 13 } //2
		$a_01_1 = {0a 20 ff 00 00 00 fe } //2
		$a_03_2 = {17 da 17 d6 8d ?? ?? ?? 01 0d 16 0a 16 07 17 da } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}