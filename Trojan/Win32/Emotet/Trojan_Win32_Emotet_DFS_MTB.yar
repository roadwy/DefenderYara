
rule Trojan_Win32_Emotet_DFS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 f8 8a 94 15 ?? ?? ?? ?? 30 10 } //1
		$a_81_1 = {70 52 55 62 54 68 48 30 49 76 6a 42 49 39 61 45 66 6a 46 72 44 68 45 74 51 79 4d 31 57 67 4d 39 66 42 47 76 43 39 4e 56 6f 4b } //1 pRUbThH0IvjBI9aEfjFrDhEtQyM1WgM9fBGvC9NVoK
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}