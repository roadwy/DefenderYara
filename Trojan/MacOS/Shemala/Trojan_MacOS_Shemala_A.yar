
rule Trojan_MacOS_Shemala_A{
	meta:
		description = "Trojan:MacOS/Shemala.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {48 89 4d f8 89 45 f4 48 89 75 e8 48 8d 85 bf df ff ff 48 8d 0d 48 02 00 00 ba 09 20 00 00 48 89 c7 48 89 ce } //03 00 
		$a_00_1 = {48 b8 00 00 00 00 00 00 00 00 48 be 28 20 00 00 00 00 00 00 bf 07 00 00 00 41 b9 02 10 00 00 41 ba ff ff ff ff 89 bd b8 df ff ff 48 89 c7 44 8b 9d b8 df ff ff 44 89 da 44 89 c9 45 89 d0 49 89 c1 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}