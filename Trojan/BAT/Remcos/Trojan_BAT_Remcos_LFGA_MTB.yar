
rule Trojan_BAT_Remcos_LFGA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.LFGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 d1 26 00 70 28 ?? ?? ?? 06 0b 73 0e 02 00 0a 0c 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59 } //2
		$a_01_1 = {41 00 69 00 6e 00 74 00 61 00 63 00 } //1 Aintac
		$a_01_2 = {35 00 34 00 35 00 42 00 47 00 47 00 50 00 37 00 39 00 54 00 50 00 35 00 4e 00 44 00 38 00 37 00 47 00 35 00 58 00 51 00 38 00 38 00 } //1 545BGGP79TP5ND87G5XQ88
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}