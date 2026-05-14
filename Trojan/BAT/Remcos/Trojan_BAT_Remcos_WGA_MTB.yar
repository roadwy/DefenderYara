
rule Trojan_BAT_Remcos_WGA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.WGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b 13 07 2b ad 00 07 07 6f ?? 01 00 0a 07 6f ?? 01 00 0a 6f ?? 01 00 0a 0c 00 73 ?? 01 00 0a 0d 2b 00 2b 00 16 13 09 11 09 } //5
		$a_03_1 = {11 05 02 16 02 8e 69 6f ?? 01 00 0a 00 11 05 6f ?? 01 00 0a 1b 13 0b 2b c6 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}