
rule Trojan_Win32_EmotetCrypt_PCC_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 1c 0f af 45 1c 03 d0 89 55 ec 8b 4d 08 03 4d e4 0f b6 11 8b 45 f4 03 45 ec 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d 18 03 4d e4 88 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}