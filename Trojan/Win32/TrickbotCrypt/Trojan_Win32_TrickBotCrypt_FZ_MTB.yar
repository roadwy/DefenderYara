
rule Trojan_Win32_TrickBotCrypt_FZ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0e 03 c2 33 d2 f7 35 90 01 04 b8 02 00 00 00 2b 05 90 01 04 0f af c5 0f af c5 48 0f af c5 03 da 03 c3 8a 14 08 8b 44 24 18 8a 18 32 da 8b 54 24 20 88 18 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}