
rule Trojan_Win32_LokiBot_DO_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {bb 01 00 00 00 90 05 05 01 90 8b c6 03 c3 90 05 05 01 90 c6 00 90 02 10 43 81 fb 90 02 04 75 90 00 } //1
		$a_02_1 = {33 c0 89 45 90 02 15 8a 90 90 90 01 04 90 05 05 01 90 80 f2 90 01 01 90 02 15 88 55 fb 90 02 15 41 81 f9 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}