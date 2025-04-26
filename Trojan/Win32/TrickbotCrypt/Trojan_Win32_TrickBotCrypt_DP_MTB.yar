
rule Trojan_Win32_TrickBotCrypt_DP_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 0f b6 45 ?? 33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 25 80 00 00 00 33 d0 8b 4d ?? 88 11 8b 55 ?? 03 55 ?? 89 55 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}