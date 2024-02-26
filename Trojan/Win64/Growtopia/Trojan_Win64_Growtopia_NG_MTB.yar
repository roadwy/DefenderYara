
rule Trojan_Win64_Growtopia_NG_MTB{
	meta:
		description = "Trojan:Win64/Growtopia.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 45 41 52 20 50 72 6f 78 79 2e 70 64 62 } //01 00  FEAR Proxy.pdb
		$a_01_1 = {34 55 6e 61 62 6c 65 20 54 6f 20 73 65 72 69 61 6c 69 7a 65 20 74 68 69 73 20 77 6f 72 6c 64 } //01 00  4Unable To serialize this world
		$a_01_2 = {62 65 74 61 5f 73 65 72 76 65 72 } //01 00  beta_server
		$a_01_3 = {4b 69 6e 67 64 6f 6d 20 50 72 65 6d 69 75 6d 20 53 6f 75 72 63 65 } //01 00  Kingdom Premium Source
		$a_01_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //00 00  CryptEncrypt
	condition:
		any of ($a_*)
 
}