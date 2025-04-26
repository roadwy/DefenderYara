
rule Trojan_BAT_DCRat_SPAN_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SPAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 16 9a 17 8d ?? ?? ?? 01 13 18 11 18 16 1f 20 9d 11 18 6f ?? ?? ?? 0a 13 10 de 03 } //2
		$a_01_1 = {37 00 77 00 6b 00 48 00 6a 00 75 00 65 00 51 00 4a 00 6b 00 46 00 78 00 4e 00 76 00 45 00 55 00 57 00 50 00 4f 00 48 00 45 00 41 00 3d 00 3d 00 } //1 7wkHjueQJkFxNvEUWPOHEA==
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}