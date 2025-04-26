
rule Trojan_Win32_LokiBot_DW_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 d2 0f 84 [0-20] bb 01 00 00 00 [0-20] 43 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {53 56 57 e8 [0-30] b0 ?? 90 05 10 01 90 8b ?? 90 05 10 01 90 81 fa ?? ?? 00 00 [0-10] 8a 92 ?? ?? ?? ?? 90 05 05 01 90 32 d0 [0-10] e8 [0-15] 81 fb ?? ?? 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}