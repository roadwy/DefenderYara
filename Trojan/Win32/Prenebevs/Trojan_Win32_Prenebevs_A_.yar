
rule Trojan_Win32_Prenebevs_A_{
	meta:
		description = "Trojan:Win32/Prenebevs.A!!Prenebevs.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 } //0a 00 
		$a_00_1 = {89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //0a 00 
		$a_00_2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 } //05 00  Mozilla/5.0 (Wind
	condition:
		any of ($a_*)
 
}