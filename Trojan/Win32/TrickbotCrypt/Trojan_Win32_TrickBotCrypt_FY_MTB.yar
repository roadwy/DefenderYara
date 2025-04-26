
rule Trojan_Win32_TrickBotCrypt_FY_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 45 f4 2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 55 0c 88 0c 02 } //5
		$a_81_1 = {77 74 4a 57 61 38 42 69 6f 76 30 52 59 74 55 2b 21 6d 6e 4f 2b 72 4e 66 2a 44 72 40 74 3c 59 26 6b 66 5a 2b 58 39 34 25 61 29 34 24 66 34 26 4b } //5 wtJWa8Biov0RYtU+!mnO+rNf*Dr@t<Y&kfZ+X94%a)4$f4&K
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5) >=5
 
}