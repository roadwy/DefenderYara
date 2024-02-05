
rule Trojan_Win32_CryptBot_RG_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec a1 90 01 04 0f af ca 8b 55 08 89 14 88 5d c3 90 02 15 55 8b ec a1 90 01 04 8b 55 08 89 14 88 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}