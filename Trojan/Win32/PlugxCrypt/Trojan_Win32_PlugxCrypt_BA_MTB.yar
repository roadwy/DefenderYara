
rule Trojan_Win32_PlugxCrypt_BA_MTB{
	meta:
		description = "Trojan:Win32/PlugxCrypt.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {99 f7 7c 24 90 0a 09 00 8b c1 90 02 08 99 90 02 05 f7 7c 24 90 01 01 8a 04 2a 8a 14 31 32 d0 90 02 08 88 14 31 90 02 14 41 3b cf 90 02 04 7c 90 00 } //0a 00 
		$a_03_1 = {99 f7 7c 24 90 01 01 90 0a 0a 00 8b c1 90 02 0a 99 f7 7c 24 90 01 01 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c e6 90 00 } //01 00 
		$a_03_2 = {85 c0 c6 44 24 90 02 02 c6 44 24 90 02 02 c6 44 24 90 02 02 c6 44 24 90 02 02 c6 44 24 90 02 02 c6 44 24 90 02 02 c6 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}