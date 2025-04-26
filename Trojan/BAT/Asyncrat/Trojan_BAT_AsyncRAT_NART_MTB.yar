
rule Trojan_BAT_AsyncRAT_NART_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 0d 00 00 70 28 ?? 00 00 06 0a dd ?? 00 00 00 26 dd ?? 00 00 00 06 2c e6 06 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a dd ?? 00 00 00 09 39 ?? 00 00 00 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 38 38 } //1 WindowsFormsApp88
		$a_01_2 = {4f 79 62 69 69 } //1 Oybii
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}