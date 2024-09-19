
rule Trojan_BAT_Rozena_KAG_MTB{
	meta:
		description = "Trojan:BAT/Rozena.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed } //5
		$a_80_1 = {58 4f 52 44 65 63 72 79 70 74 } //XORDecrypt  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}