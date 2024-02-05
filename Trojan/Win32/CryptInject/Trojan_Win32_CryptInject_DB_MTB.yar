
rule Trojan_Win32_CryptInject_DB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {85 c9 74 13 52 b8 00 00 00 00 8a 03 01 c2 8a 02 88 03 5a 49 4b eb e9 } //01 00 
		$a_01_1 = {55 50 58 30 } //01 00 
		$a_01_2 = {55 50 58 31 } //00 00 
	condition:
		any of ($a_*)
 
}