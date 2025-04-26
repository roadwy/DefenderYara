
rule Trojan_Win32_Ekstak_ASFO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 54 72 46 00 8e cf 42 00 00 d2 0a 00 58 94 5f 1e 4e 1e 42 00 00 d4 00 00 de 09 02 } //5
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 64 45 46 00 92 a2 42 00 00 d2 0a 00 fa 3f 41 7d eb 10 42 00 00 d4 00 00 2a 8f 4c cf 00 00 01 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}