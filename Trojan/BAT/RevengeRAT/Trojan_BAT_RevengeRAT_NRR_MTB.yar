
rule Trojan_BAT_RevengeRAT_NRR_MTB{
	meta:
		description = "Trojan:BAT/RevengeRAT.NRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 58 00 00 0a 25 26 73 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 25 26 1f 24 28 90 01 01 00 00 06 25 26 1f 35 28 90 01 01 00 00 06 25 26 28 90 01 01 00 00 06 25 26 28 90 01 01 00 00 0a 25 26 90 00 } //5
		$a_01_1 = {41 65 73 4f 6e 75 79 65 47 61 } //1 AesOnuyeGa
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}