
rule Trojan_Win32_CobaltStrike_UWW_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.UWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 35 36 c7 21 a3 66 a3 ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 0f b6 4d fd 0f b7 15 ?? ?? ?? ?? 0b ca 03 c1 88 45 fd 8b 45 8c 05 8b 00 00 00 89 85 ?? fd ff ff b9 5d 00 00 00 66 89 0d } //4
		$a_03_1 = {2b c8 8b 85 70 fe ff ff 1b c2 33 f1 33 f8 89 75 b4 89 7d b8 0f bf 4d e4 03 0d ?? ?? ?? ?? 0f bf 55 e4 0b d1 66 89 55 e4 eb } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}