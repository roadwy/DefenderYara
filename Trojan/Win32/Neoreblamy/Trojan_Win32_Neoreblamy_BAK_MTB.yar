
rule Trojan_Win32_Neoreblamy_BAK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 0c 0f af 45 fc 8b 4d 08 2b c8 89 4d f8 8b 45 f8 8b e5 5d c3 } //3
		$a_03_1 = {ff 34 81 ff 34 b7 e8 ?? ?? ?? ?? 83 c4 10 89 04 b7 46 3b f3 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}