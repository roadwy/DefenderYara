
rule Trojan_Win32_Emotetcrypt_FA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 32 88 14 29 8b 54 24 90 01 01 88 04 32 8b 44 24 90 01 01 0f b6 04 30 8b 54 24 90 01 01 0f b6 14 0a 03 c2 33 d2 bd 90 01 04 f7 f5 8b 44 24 90 01 01 8b 6c 24 90 01 01 83 c5 01 89 6c 24 90 01 01 03 d3 03 54 24 90 01 01 03 d7 0f b6 14 02 8b 44 24 90 01 01 30 54 28 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}