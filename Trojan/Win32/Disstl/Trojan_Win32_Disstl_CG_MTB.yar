
rule Trojan_Win32_Disstl_CG_MTB{
	meta:
		description = "Trojan:Win32/Disstl.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 92 45 c2 1b b8 30 48 0a f7 eb 05 9a 04 08 64 48 eb 03 } //1
		$a_01_1 = {bb 1c 52 90 eb 01 b7 e9 c1 01 00 00 eb 02 f3 02 8b 02 eb 01 f3 33 42 04 72 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}