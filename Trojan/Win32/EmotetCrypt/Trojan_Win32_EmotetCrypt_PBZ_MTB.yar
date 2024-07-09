
rule Trojan_Win32_EmotetCrypt_PBZ_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 55 17 02 14 33 88 10 88 0c 33 0f b6 00 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 4d 1c 03 55 10 8a 04 32 02 45 17 32 04 39 88 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}