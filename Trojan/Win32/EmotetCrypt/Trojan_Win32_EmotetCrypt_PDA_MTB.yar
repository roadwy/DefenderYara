
rule Trojan_Win32_EmotetCrypt_PDA_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 20 8a 0c 32 8b 44 24 14 02 4c 24 30 8b 54 24 24 32 0c 02 83 c0 01 83 6c 24 18 01 88 48 ff 89 44 24 14 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_PDA_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 8b 44 24 90 01 01 02 4c 24 90 01 01 8b 54 24 90 01 01 32 0c 02 83 c0 01 83 6c 24 90 01 01 01 88 48 ff 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}