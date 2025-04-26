
rule Trojan_Win32_LokiBot_SPQC_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.SPQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 fe c0 34 5b 04 78 34 99 04 65 88 04 37 46 3b f3 72 eb } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}