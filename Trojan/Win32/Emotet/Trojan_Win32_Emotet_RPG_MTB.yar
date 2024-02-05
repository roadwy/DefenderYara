
rule Trojan_Win32_Emotet_RPG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d 90 01 04 2b 0d 90 01 04 8b 55 0c 8b 45 e8 88 04 0a e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}