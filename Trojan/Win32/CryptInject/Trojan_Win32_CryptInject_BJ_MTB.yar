
rule Trojan_Win32_CryptInject_BJ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 fb 70 0a 00 00 75 90 01 01 56 56 56 56 ff 15 90 01 04 56 56 56 56 56 56 ff 15 90 01 04 56 8d 85 18 fb ff ff 50 ff 15 90 01 04 e8 90 01 04 8b 8d 14 fb ff ff 30 04 39 81 fb 9b 0a 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_BJ_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BJ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 51 52 56 57 39 } //01 00  PQRVW9
		$a_01_1 = {50 51 52 56 57 3d 77 } //01 00  PQRVW=w
		$a_01_2 = {50 51 52 56 57 3b 4d } //01 00  PQRVW;M
		$a_01_3 = {50 51 52 56 57 3b 45 } //01 00  PQRVW;E
		$a_01_4 = {50 51 52 56 57 3b 75 } //01 00  PQRVW;u
		$a_01_5 = {77 69 6e 73 70 6f 6f 6c 2e 64 72 76 } //00 00  winspool.drv
	condition:
		any of ($a_*)
 
}