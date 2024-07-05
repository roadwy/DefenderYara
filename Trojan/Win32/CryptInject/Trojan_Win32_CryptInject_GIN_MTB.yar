
rule Trojan_Win32_CryptInject_GIN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.GIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 8b c6 be 03 00 00 00 33 d2 f7 f6 8b 45 10 83 c4 08 32 0c 10 8d 55 f8 51 52 e8 43 08 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}