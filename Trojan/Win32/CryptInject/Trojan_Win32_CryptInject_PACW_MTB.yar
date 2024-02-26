
rule Trojan_Win32_CryptInject_PACW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PACW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 81 c2 a5 03 ea c5 31 33 ba a8 04 2c b0 21 c2 4a 81 c3 01 00 00 00 89 c2 09 d2 81 c0 40 26 ff b3 39 fb 75 cf } //01 00 
		$a_01_1 = {8d 34 31 52 8b 04 24 83 c4 04 b8 45 8a 5c 25 09 c2 8b 36 42 21 d0 81 e6 ff 00 00 00 52 5a 81 c1 01 00 00 00 29 d2 81 f9 f4 01 00 00 75 05 b9 } //00 00 
	condition:
		any of ($a_*)
 
}