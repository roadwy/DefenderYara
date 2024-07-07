
rule Trojan_Win32_EmotetCrypt_VA_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d0 0f b6 c0 8b ce 90 02 14 8b d7 0f b6 4d 90 01 01 47 2b 15 90 01 04 8a 04 90 01 01 b9 90 01 04 90 17 04 01 01 01 01 30 31 32 33 90 01 02 8b 45 90 01 01 3b 7d 90 01 01 0f 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}