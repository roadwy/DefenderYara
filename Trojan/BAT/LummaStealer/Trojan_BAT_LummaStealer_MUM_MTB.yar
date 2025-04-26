
rule Trojan_BAT_LummaStealer_MUM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.MUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 69 13 26 08 17 58 20 ?? ?? ?? 00 5d 0c 09 06 08 91 58 20 ?? ?? ?? 00 5d 0d 06 08 91 13 27 06 08 06 09 91 9c 06 09 11 27 9c 06 08 91 06 09 91 58 } //4
		$a_03_1 = {6a 5b 26 11 2b 11 2e 37 07 11 33 11 33 5b 13 31 16 13 34 12 1f 28 19 00 00 0a 12 34 28 ?? ?? ?? 0a 26 16 13 35 12 28 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 35 } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}