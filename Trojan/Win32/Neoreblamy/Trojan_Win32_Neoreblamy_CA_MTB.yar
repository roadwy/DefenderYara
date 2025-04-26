
rule Trojan_Win32_Neoreblamy_CA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f af 45 fc 8b 4d f8 2b c8 8b 45 f4 ff 34 8f ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d f4 89 04 b1 46 8b 45 f0 03 c3 3b f0 72 } //5
		$a_03_1 = {0f b6 04 10 50 8b 45 10 03 45 f8 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ff ff 59 59 8b 4d f0 03 4d f4 88 01 eb } //4
		$a_01_2 = {8b 45 10 03 45 f8 33 d2 f7 35 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1) >=5
 
}