
rule Trojan_Win32_RustyStealer_ARY_MTB{
	meta:
		description = "Trojan:Win32/RustyStealer.ARY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 18 03 74 24 5c 03 6c 24 14 03 5c 24 54 03 54 24 30 03 7c 24 68 01 84 24 c8 00 00 00 8b 44 24 24 89 b4 24 d8 00 00 00 31 74 24 04 31 6c 24 38 c1 44 24 38 10 89 ac 24 c4 00 00 00 8b 6c 24 10 31 5c 24 58 89 94 24 b0 00 00 00 c1 44 24 58 10 31 7c 24 48 89 9c 24 9c 00 00 00 8b 5c 24 64 89 bc 24 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}