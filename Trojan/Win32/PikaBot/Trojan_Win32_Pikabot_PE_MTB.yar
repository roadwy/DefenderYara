
rule Trojan_Win32_Pikabot_PE_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 0f b6 54 15 90 01 01 33 ca 8b 45 90 01 01 03 45 90 01 01 88 08 eb 90 01 01 8b 4d 90 01 01 51 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}