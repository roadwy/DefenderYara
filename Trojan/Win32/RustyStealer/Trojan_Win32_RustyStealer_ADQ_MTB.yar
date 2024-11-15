
rule Trojan_Win32_RustyStealer_ADQ_MTB{
	meta:
		description = "Trojan:Win32/RustyStealer.ADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 9c 24 8c 00 00 00 c1 84 24 8c 00 00 00 0c 8b 5c 24 3c 33 84 24 e8 00 00 00 c1 c5 10 01 ac 24 } //2
		$a_01_1 = {c1 44 24 24 07 33 84 24 e0 00 00 00 89 c2 89 d8 c1 c2 07 c1 c0 07 89 54 24 48 8b 54 24 68 89 44 24 58 c1 c2 07 e9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}