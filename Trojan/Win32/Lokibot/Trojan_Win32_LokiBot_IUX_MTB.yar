
rule Trojan_Win32_LokiBot_IUX_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.IUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d fc 8b 45 fc 8b 55 08 01 d0 80 30 b8 41 81 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}