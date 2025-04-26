
rule Trojan_Win32_Neoreblamy_BV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8b 45 ?? 2b ca 03 4d ?? ff 34 8f ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d ?? 89 04 b1 46 8b 45 ?? 03 c3 3b f0 } //10
		$a_03_1 = {8b 45 08 8a 1c 07 8b c7 99 f7 7d ?? 8b f2 8a d1 8a cb e8 ?? ?? 00 00 8b 4d 10 8a 14 0e 8a c8 e8 } //5
		$a_01_2 = {56 0f b6 f1 0f b6 c2 8b c8 23 ce 03 c9 2b c1 03 c6 5e c3 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5) >=10
 
}