
rule Trojan_Win32_Neoreblamy_BZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8b 45 ?? 03 4d ?? ff 34 8b ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d ?? 89 04 b1 46 8b 45 ?? 03 c7 3b f0 72 } //10
		$a_03_1 = {33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ff ff 59 59 50 8d 4d e4 e8 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}