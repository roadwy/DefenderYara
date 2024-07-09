
rule Trojan_Win32_TrickBotCrypt_DL_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 0f b6 4d ?? 33 c1 8b 55 ?? 2b 55 ?? 0f b6 ca 81 e1 80 00 00 00 33 c1 8b 55 ?? 88 02 8b 45 ?? 03 45 ?? 89 45 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}