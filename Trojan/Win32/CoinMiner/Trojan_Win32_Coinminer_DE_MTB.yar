
rule Trojan_Win32_Coinminer_DE_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 f1 81 c1 01 00 00 00 31 18 89 f1 40 be 72 a8 9d cc 83 ec 04 89 0c 24 5e 81 e9 9f f1 31 da 39 d0 75 } //01 00 
		$a_01_1 = {81 c2 01 00 00 00 29 f6 89 f0 81 fa 01 2a 00 03 75 } //00 00 
	condition:
		any of ($a_*)
 
}