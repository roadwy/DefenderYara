
rule Ransom_Win32_Nemty_PF_MTB{
	meta:
		description = "Ransom:Win32/Nemty.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ba 04 00 00 00 6b c2 00 8b 4d ec 8b 14 01 89 55 d4 b8 04 00 00 00 c1 e0 00 8b 4d ec 8b 14 01 89 55 90 01 01 b8 04 00 00 00 d1 e0 8b 4d ec 8b 14 01 89 55 90 01 01 81 3d 90 01 04 85 0f 00 00 75 90 00 } //1
		$a_02_1 = {8a 55 fc 88 55 ff 0f b6 45 ff c1 e0 04 88 45 ff 0f b6 4d ff 81 e1 c0 00 00 00 88 4d ff 0f b6 55 fd 0f b6 45 ff 0b d0 88 55 fd 81 3d 90 01 04 7b 0e 00 00 75 90 09 0a 00 c7 05 90 01 04 60 5a 20 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}