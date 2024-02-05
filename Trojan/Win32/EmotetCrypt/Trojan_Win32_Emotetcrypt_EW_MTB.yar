
rule Trojan_Win32_Emotetcrypt_EW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 28 8b 54 24 90 01 01 8b 44 24 90 01 01 0f b6 04 02 8b 54 24 90 01 01 0f b6 14 2a 03 c2 33 d2 bd 90 01 04 f7 f5 8b 44 24 90 01 01 2b d3 2b 15 90 01 04 2b d6 03 15 90 01 04 0f b6 14 02 30 54 0f ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}