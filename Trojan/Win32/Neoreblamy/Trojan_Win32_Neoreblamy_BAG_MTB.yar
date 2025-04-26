
rule Trojan_Win32_Neoreblamy_BAG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 73 3b 8b 45 10 03 45 fc 33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ?? 59 59 50 8d 4d e4 e8 ?? ?? ?? ?? eb } //4
		$a_03_1 = {99 f7 f9 a5 a5 a5 8b 4d fc 5f 5e 5b 8b ?? c1 [0-04] 2d 2c 01 00 00 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}