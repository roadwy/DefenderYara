
rule Trojan_Win32_EmotetCrypt_DC_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8d 0c 39 f7 e1 8b cb 8d 7f ?? c1 ea 02 83 c3 06 6b c2 0d 2b c8 0f b6 44 8d ?? 30 47 ff 81 fb 00 34 02 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}