
rule Trojan_BAT_Heracles_AYE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 28 13 00 00 0a 2d 07 07 28 14 00 00 0a 26 00 06 28 0c 00 00 06 28 0d 00 00 06 13 04 09 11 04 28 15 00 00 0a 20 10 27 00 00 28 16 00 00 0a 09 28 17 00 00 0a 26 de 06 } //7
		$a_01_1 = {64 72 6f 70 48 69 6a 61 63 6b 44 6c 6c } //3 dropHijackDll
		$a_01_2 = {44 65 63 6f 6d 70 72 65 73 73 50 64 66 46 72 6f 6d 42 61 73 65 36 34 } //1 DecompressPdfFromBase64
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=11
 
}