
rule Trojan_Win32_Emotetcrypt_VW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8b 15 90 02 04 8a 04 10 90 17 04 01 01 01 01 31 32 30 33 90 02 0a 7c 90 01 01 8a 90 01 03 8b 90 01 03 8a 90 01 03 5f 90 02 02 88 90 02 02 88 90 02 02 5d 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}