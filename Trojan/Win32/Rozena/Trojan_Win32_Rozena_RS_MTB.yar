
rule Trojan_Win32_Rozena_RS_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 9d 24 e7 ff ff 8d b5 24 e7 ff ff 80 f3 90 8b cf 2b f7 ba d5 18 00 00 } //01 00 
		$a_01_1 = {8a 8d 24 e7 ff ff 80 f1 90 8a 04 0e 8d 49 01 32 c3 88 41 ff } //01 00 
		$a_01_2 = {8a 9d 24 e7 ff ff 8b cf 56 8d b5 24 e7 ff ff 80 f3 90 2b f7 ba d5 18 00 00 } //01 00 
		$a_01_3 = {8a 85 24 e7 ff ff 8a c8 80 f1 90 32 c1 88 06 8a 04 0e } //00 00 
	condition:
		any of ($a_*)
 
}