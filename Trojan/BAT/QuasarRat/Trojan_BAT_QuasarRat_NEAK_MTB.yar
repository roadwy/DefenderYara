
rule Trojan_BAT_QuasarRat_NEAK_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_00_0 = {38 32 00 00 00 28 06 00 00 0a 11 00 6f 07 00 00 0a 28 08 00 00 0a 13 03 } //10
		$a_01_1 = {52 65 63 72 79 70 74 65 64 } //5 Recrypted
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}