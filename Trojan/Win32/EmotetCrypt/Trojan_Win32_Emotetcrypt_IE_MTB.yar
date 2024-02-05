
rule Trojan_Win32_Emotetcrypt_IE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ca 2b 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 03 ca 2b 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 00 } //01 00 
		$a_81_1 = {65 76 34 4c 31 55 62 28 79 64 4e 7a 62 32 78 53 37 33 49 58 6c 3e 49 2a 25 4e 46 23 4f 37 65 53 43 5e } //00 00 
	condition:
		any of ($a_*)
 
}