
rule Trojan_Win32_CryptoBot_RDB_MTB{
	meta:
		description = "Trojan:Win32/CryptoBot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 75 08 83 c6 02 8a 04 1a 33 d2 30 01 8d 04 0f f7 75 08 8d 49 02 8a 14 1a 30 51 ff } //00 00 
	condition:
		any of ($a_*)
 
}