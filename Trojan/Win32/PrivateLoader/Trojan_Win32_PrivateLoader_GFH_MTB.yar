
rule Trojan_Win32_PrivateLoader_GFH_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.GFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 45 dc c6 45 fe 45 33 c1 69 c0 00 b3 ff ff 66 89 45 f0 eb 2f } //10
		$a_03_1 = {99 8b f0 a1 ?? ?? ?? ?? 33 d1 33 f0 2b c6 8b 75 e0 1b ca 8b 15 ?? ?? ?? ?? a3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}