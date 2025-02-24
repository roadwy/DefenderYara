
rule Trojan_Win32_Neoreblamy_BAN_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {59 33 d2 8b c6 f7 f1 8b 45 08 ff 34 ?? ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72 } //4
		$a_03_1 = {55 8b ec 83 ec ?? 8b 45 08 03 45 0c 89 45 } //1
		$a_01_2 = {8b 45 08 23 45 0c 89 45 f4 8b 45 08 23 45 0c 89 45 } //1
		$a_03_3 = {2b c1 0f af 45 ?? 0f b6 4d ?? 8b 55 ?? 0f af d1 03 c2 8b 4d ?? 2b c8 0f b6 45 } //3
		$a_03_4 = {2b c2 0f af 45 ?? 0f b6 55 ?? 8b 75 ?? 0f af f2 03 c6 03 c8 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3+(#a_03_4  & 1)*2) >=5
 
}