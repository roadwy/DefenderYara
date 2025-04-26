
rule Ransom_Win32_EnmityRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/EnmityRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {03 d2 33 b4 d0 08 c0 00 00 33 8c d0 0c c0 00 00 33 b4 07 08 a0 00 00 33 8c 07 0c a0 00 00 33 b4 03 08 e0 00 00 8b 55 c8 33 8c 03 0c e0 00 00 8b de 89 75 08 } //2
		$a_01_1 = {45 6e 6d 69 74 79 5c 52 65 6c 65 61 73 65 5c 45 6e 6d 69 74 79 2e 70 64 62 } //1 Enmity\Release\Enmity.pdb
		$a_01_2 = {43 3a 5c 6b 65 79 66 6f 72 75 6e 6c 6f 63 6b 5c 4b 65 79 2e 74 78 74 } //1 C:\keyforunlock\Key.txt
		$a_01_3 = {43 3a 5c 6b 65 79 66 6f 72 75 6e 6c 6f 63 6b 5c 52 53 41 64 65 63 72 2e 6b 65 79 73 } //1 C:\keyforunlock\RSAdecr.keys
		$a_01_4 = {69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 74 00 78 00 74 00 } //1 information.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}