
rule Trojan_BAT_Androm_AAUF_MTB{
	meta:
		description = "Trojan:BAT/Androm.AAUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 2b 00 00 70 0a 06 20 f7 07 00 00 0c 12 02 28 ?? 00 00 0a 1f 54 0c 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 07 } //3
		$a_01_1 = {2f 00 2f 00 49 00 2f 00 2f 00 6e 00 2f 00 2f 00 76 00 2f 00 2f 00 6f 00 2f 00 2f 00 6b 00 2f 00 2f 00 65 00 2f 00 2f 00 } //1 //I//n//v//o//k//e//
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}