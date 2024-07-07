
rule Trojan_Win32_ICLoader_JLK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.JLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 04 c1 e2 04 0b ca eb 05 33 c9 8a 0c 18 8b 55 f4 8b 75 08 88 0c 32 42 89 55 f4 40 8b 75 ec 8a 55 ff 46 d0 e2 83 fe 08 89 75 ec 88 55 ff 0f 8c 9b fd ff ff eb 6e 8a 4d f8 84 c9 74 14 8a 4c 18 fc c6 45 f8 00 81 e1 fc 00 00 00 c1 e1 05 40 eb 0d } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}