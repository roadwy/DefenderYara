
rule Trojan_Win32_VirRansom_DM_MTB{
	meta:
		description = "Trojan:Win32/VirRansom.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 b9 03 00 00 00 f7 f9 8b 45 e8 0f be 0c 10 8b 95 ?? fd ff ff 0f b6 44 15 f4 33 c1 8b 8d ?? fd ff ff 88 44 0d f4 eb ba } //10
		$a_00_1 = {0f b6 55 ef 0f b6 45 f7 3b d0 75 0c 0f b6 4d f0 0f b6 55 f8 3b ca 74 0e 8b 45 fc 83 c0 01 89 45 fc } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}