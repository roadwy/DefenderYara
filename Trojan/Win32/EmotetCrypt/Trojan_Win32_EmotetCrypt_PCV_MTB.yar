
rule Trojan_Win32_EmotetCrypt_PCV_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0e 0f b6 04 0f 03 c2 99 b9 90 01 04 f7 f9 88 54 24 90 01 01 ff 15 90 01 04 0f b6 54 24 90 01 01 a1 90 01 04 8a 0c 02 8b 44 24 90 01 01 30 0c 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}