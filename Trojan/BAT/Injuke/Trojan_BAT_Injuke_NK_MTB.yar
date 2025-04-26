
rule Trojan_BAT_Injuke_NK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 36 00 00 01 13 03 20 ?? 00 00 00 28 ?? 00 00 06 39 ?? fe ff ff 26 20 ?? 00 00 00 38 ?? fe ff ff 02 16 11 03 16 02 8e 69 1f 10 da } //3
		$a_01_1 = {73 00 61 00 67 00 65 00 70 00 72 00 6f 00 6d 00 6f 00 73 00 74 00 61 00 72 00 5f 00 69 00 6e 00 73 00 74 00 72 00 75 00 6d 00 65 00 6e 00 74 00 32 00 2e 00 65 00 78 00 65 00 } //1 sagepromostar_instrument2.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}