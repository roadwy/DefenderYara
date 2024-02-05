
rule Trojan_Win32_Emotetcrypt_VQ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 02 02 8b 0d 90 02 04 8a 14 90 02 02 8b 44 90 02 02 30 14 90 02 02 47 3b 90 02 04 0f 8c 90 02 04 8a 90 02 04 8b 90 02 04 8a 90 02 04 5e 5d 5b 88 90 02 02 88 90 02 02 5f 83 90 02 02 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}