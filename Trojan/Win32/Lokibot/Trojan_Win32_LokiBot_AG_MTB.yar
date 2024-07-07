
rule Trojan_Win32_LokiBot_AG_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 38 88 45 90 02 40 8b 45 90 02 64 8b 84 85 90 02 04 33 d2 8a 55 90 01 01 33 c2 90 02 40 8b 55 90 02 01 88 02 90 02 20 ff 4d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}