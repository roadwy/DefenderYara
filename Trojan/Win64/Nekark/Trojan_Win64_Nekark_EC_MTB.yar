
rule Trojan_Win64_Nekark_EC_MTB{
	meta:
		description = "Trojan:Win64/Nekark.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {40 32 2c 02 41 88 2c 3c 48 83 c7 01 49 39 fd 0f 84 0e 01 00 00 } //01 00 
		$a_81_1 = {62 6a 7a 63 6b 6e 70 6a 71 7c 7a 62 7a 6e 77 68 77 64 67 61 6f 6c 79 71 78 7a 6b 68 70 77 64 6c 62 6a 6a 63 } //00 00  bjzcknpjq|zbznwhwdgaolyqxzkhpwdlbjjc
	condition:
		any of ($a_*)
 
}