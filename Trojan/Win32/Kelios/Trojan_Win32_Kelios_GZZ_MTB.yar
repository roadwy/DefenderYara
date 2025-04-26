
rule Trojan_Win32_Kelios_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 da 66 0f ba e0 14 66 81 fd d7 7a 88 0c 14 66 ff c8 8b 44 25 00 } //5
		$a_01_1 = {80 f1 91 fe c9 f5 d0 c9 32 d9 66 89 14 0c } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}