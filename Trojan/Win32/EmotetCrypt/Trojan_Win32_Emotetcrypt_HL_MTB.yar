
rule Trojan_Win32_Emotetcrypt_HL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0a 03 c3 99 f7 fe 8b 44 24 ?? 8a 04 08 8b 74 24 ?? 2b 54 24 ?? 8b da 8b 54 24 ?? 0f b6 14 1a 88 14 0e 8b 54 24 ?? 88 04 1a 8b 44 24 ?? 0f b6 04 18 8b 54 24 ?? 0f b6 14 0a 03 c2 99 be ?? ?? ?? ?? f7 fe 8b 44 24 ?? 8b 74 24 ?? 2b d7 03 54 24 ?? 0f b6 14 02 30 54 2e } //1
		$a_81_1 = {2b 5e 6c 63 3f 46 55 50 52 25 36 44 36 40 68 57 5e 40 68 5a 75 30 52 59 54 35 74 7a 2b 61 75 4f 24 5a 59 5a 61 35 44 63 74 5a 39 3e 2b 25 63 75 52 59 25 75 2a 31 39 6e } //1 +^lc?FUPR%6D6@hW^@hZu0RYT5tz+auO$ZYZa5DctZ9>+%cuRY%u*19n
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}