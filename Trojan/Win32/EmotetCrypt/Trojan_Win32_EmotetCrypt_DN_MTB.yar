
rule Trojan_Win32_EmotetCrypt_DN_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 8d c4 30 47 02 b8 90 01 04 8b 4d f4 8d 0c 39 f7 e1 8b cb 8d 7f 04 c1 ea 02 83 c3 04 6b c2 0d 2b c8 0f b6 44 8d c8 30 47 ff 81 fb 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}