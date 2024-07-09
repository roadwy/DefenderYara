
rule Trojan_Win32_LokiBot_AG_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 38 88 45 [0-40] 8b 45 [0-64] 8b 84 85 [0-04] 33 d2 8a 55 ?? 33 c2 [0-40] 8b 55 [0-01] 88 02 [0-20] ff 4d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}