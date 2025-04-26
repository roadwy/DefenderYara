
rule Trojan_Win32_LokiBot_IUY_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.IUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc 8b 5d 08 eb 05 80 37 47 eb 07 8b 7d fc 01 df eb f4 90 40 3d 08 5e 00 00 75 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}