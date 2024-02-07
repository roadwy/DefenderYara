
rule Trojan_Win32_Lazy_CG_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 5a 01 8d 52 02 80 eb 61 85 ff 74 17 c0 e0 04 2c 10 0a c3 32 c1 32 c7 88 06 32 e8 83 c6 02 83 c5 02 eb 0e 8a c8 bf 01 00 00 00 fe c9 c0 e1 04 0a cb 8a 02 84 c0 75 } //01 00 
		$a_01_1 = {8a 42 01 8d 52 02 c0 e1 04 8d 76 01 80 e9 10 2c 61 0a c8 32 cb 80 f1 d0 88 4e ff 8a 0a 84 c9 75 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}