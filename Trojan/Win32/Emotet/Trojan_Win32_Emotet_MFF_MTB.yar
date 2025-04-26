
rule Trojan_Win32_Emotet_MFF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 d1 03 8d ?? ?? ?? ?? 29 f0 8a 5d f3 80 f3 84 89 8d ?? ?? ?? ?? 8b 8d f0 fe ff ff 8b 55 0c 8a 3c 0a 88 bd df fe ff ff 02 9d df fe ff ff 88 9d df fe ff ff 8b 8d f0 fe ff ff 89 85 c4 fe ff ff } //4
		$a_03_1 = {66 b8 a1 6c 8a 4c 24 4b 80 f1 ff 66 8b 54 24 ?? 88 4c 24 4b 66 29 d0 66 89 44 24 1e 66 8b 44 24 1e 66 8b 54 24 38 66 81 f2 55 ?? 66 39 d0 73 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4) >=8
 
}