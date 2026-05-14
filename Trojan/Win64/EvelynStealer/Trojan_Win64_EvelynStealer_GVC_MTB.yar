
rule Trojan_Win64_EvelynStealer_GVC_MTB{
	meta:
		description = "Trojan:Win64/EvelynStealer.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c0 b9 41 00 00 00 f3 48 ab 48 8d 84 24 20 05 00 00 b9 04 01 00 00 48 89 44 24 68 48 89 c2 48 8b 05 72 28 16 00 48 89 84 24 a8 00 00 00 ff d0 83 e8 01 89 84 24 80 00 00 00 3d 02 01 00 00 0f 87 91 13 00 00 } //1
		$a_01_1 = {61 70 70 5f 62 6f 75 6e 64 5f 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 app_bound_encrypted_key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}