
rule Trojan_Win32_Emotetcrypt_VO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 02 01 a1 90 02 04 8a 0c 90 02 01 8b 44 90 02 02 30 0c 90 02 06 3b 90 02 03 0f 8c 90 02 04 8b 90 02 03 8a 90 02 03 8a 90 02 03 5f 90 02 02 88 90 02 01 88 90 02 02 5b 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}