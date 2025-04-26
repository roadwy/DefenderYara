
rule Trojan_Win32_LokiBot_DU_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 d2 0f 84 [0-20] bb 01 00 00 00 [0-20] 43 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8b eb 81 fd [0-10] 8a 85 [0-10] 80 f2 6c [0-10] e8 [0-20] ff 43 81 fb ?? ?? 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}