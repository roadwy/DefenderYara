
rule Trojan_Win32_Emotetcrypt_FH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 75 ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f1 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f0 8b 45 ?? 88 14 30 } //1
		$a_81_1 = {55 70 42 46 39 48 79 75 2b 62 6d 4c 30 59 4c 70 70 42 57 76 21 40 5a 66 5a 51 6b 61 62 6c 26 72 68 } //1 UpBF9Hyu+bmL0YLppBWv!@ZfZQkabl&rh
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}