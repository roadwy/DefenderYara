
rule Trojan_BAT_Barys_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Barys.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {de 03 26 de 00 72 ?? 00 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 14 16 8d ?? 00 00 01 6f ?? 00 00 0a 26 de 03 } //1
		$a_03_1 = {0a 2c 10 06 16 31 0c 06 20 ?? 03 00 00 5a 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}