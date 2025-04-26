
rule Trojan_Win32_Agenttesla_PGA_MTB{
	meta:
		description = "Trojan:Win32/Agenttesla.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 00 45 00 31 00 46 00 42 00 41 00 30 00 45 00 2d 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 30 00 31 00 34 } //5
		$a_01_1 = {30 00 34 00 30 00 32 00 45 00 37 00 32 00 36 00 35 00 36 00 43 00 36 00 46 00 36 00 } //5 0402E72656C6F6
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}