
rule Trojan_Win32_LokiBot_GM_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 06 88 45 90 02 40 8a 84 85 90 01 04 32 45 90 01 01 8b 55 90 01 01 88 02 90 02 30 ff 4d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}