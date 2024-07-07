
rule Trojan_Win32_LokiBot_RAO_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 3c 28 0f 90 02 10 83 ed 58 90 02 10 83 c5 54 7d 90 02 10 eb 90 02 30 50 90 02 10 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}