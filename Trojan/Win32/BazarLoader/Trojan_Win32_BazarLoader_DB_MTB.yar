
rule Trojan_Win32_BazarLoader_DB_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 1c 24 83 c3 0c 89 5c 24 20 8b 5c 24 20 8b 1b 89 1a 8b 1c 24 } //10
		$a_01_1 = {8b 44 24 10 8b 4c 24 04 89 01 8b 44 24 24 8b 4c 24 20 89 01 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}