
rule Trojan_Win32_CryptoBot_RDA_MTB{
	meta:
		description = "Trojan:Win32/CryptoBot.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {30 01 8d 04 0f f7 75 08 0f b6 04 32 33 d2 30 41 01 8d 04 0b f7 75 08 0f b6 04 32 33 d2 30 41 02 } //00 00 
	condition:
		any of ($a_*)
 
}