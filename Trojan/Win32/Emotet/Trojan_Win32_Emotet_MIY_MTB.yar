
rule Trojan_Win32_Emotet_MIY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 f7 8a 6c 24 7b 88 8c 24 b7 00 00 00 28 ea 81 f6 fd 23 b6 64 66 c7 84 24 ?? ?? ?? ?? 6a 8a 88 54 04 5b 01 f8 89 84 24 84 00 00 00 bf 63 2f ab 49 8b 5c 24 30 89 44 24 10 89 d8 f7 e7 8b 7c 24 34 69 ff 63 2f ab 49 01 fa 89 84 24 b8 00 00 00 } //5
		$a_03_1 = {28 c8 8a 54 24 6b 88 84 24 ?? ?? ?? ?? 8b 74 24 38 83 c6 14 66 8b 7c 24 4c 66 81 cf 2d 6b 66 89 bc 24 ?? ?? ?? ?? 8b 5c 24 48 83 f3 ff 8a 44 24 7b 89 9c 24 ?? ?? ?? ?? 34 e4 89 74 24 5c 66 c7 84 24 ?? ?? ?? ?? 43 32 38 d0 74 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}