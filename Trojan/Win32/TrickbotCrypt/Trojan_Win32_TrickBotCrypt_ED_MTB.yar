
rule Trojan_Win32_TrickBotCrypt_ED_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 14 03 d0 a0 90 01 04 f6 eb 2a c8 8a c1 b1 1f f6 e9 8b 4c 24 90 01 01 02 04 31 2a 05 90 01 04 30 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_ED_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0f 89 44 24 10 0f b6 04 0e 03 c2 33 d2 f7 35 90 01 04 b8 02 00 00 00 2b 05 90 01 04 45 0f af c3 0f af c3 48 03 15 90 01 04 0f af c3 03 c2 8a 14 08 8b 44 24 10 30 10 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}