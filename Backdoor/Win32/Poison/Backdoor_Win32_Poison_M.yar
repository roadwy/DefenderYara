
rule Backdoor_Win32_Poison_M{
	meta:
		description = "Backdoor:Win32/Poison.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 31 92 33 c9 69 c0 05 4b 56 ac 83 c0 01 89 84 8e d9 08 00 00 83 c1 01 83 f9 22 72 e8 d9 e8 db be 61 09 00 00 c7 86 d1 08 00 00 00 00 00 00 c7 86 d5 08 00 00 50 00 00 00 e8 5d ff ff ff 57 bf 1e 00 00 00 e8 52 ff ff ff 83 ef 01 75 f6 5f 64 a1 30 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}