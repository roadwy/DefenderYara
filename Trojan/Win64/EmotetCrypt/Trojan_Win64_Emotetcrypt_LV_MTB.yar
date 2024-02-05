
rule Trojan_Win64_Emotetcrypt_LV_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 f7 ee 41 03 d6 41 ff c6 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 42 8a 54 04 90 01 01 2b c8 48 63 c1 49 8b ca 42 32 14 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}