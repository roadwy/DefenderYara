
rule Trojan_Win32_LokiBot_DU_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 d2 0f 84 90 02 20 bb 01 00 00 00 90 02 20 43 81 fb 90 01 04 75 90 00 } //1
		$a_03_1 = {8b eb 81 fd 90 02 10 8a 85 90 02 10 80 f2 6c 90 02 10 e8 90 02 20 ff 43 81 fb 90 01 02 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}