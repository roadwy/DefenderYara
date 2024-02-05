
rule Trojan_Win32_EmotetCrypt_PCZ_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 20 8a 0c 32 8b 44 24 10 02 4c 24 30 8b 54 24 24 32 0c 02 40 ff 4c 24 18 88 48 ff 89 44 24 10 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}