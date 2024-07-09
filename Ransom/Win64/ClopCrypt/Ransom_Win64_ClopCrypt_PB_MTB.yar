
rule Ransom_Win64_ClopCrypt_PB_MTB{
	meta:
		description = "Ransom:Win64/ClopCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 00 6f 00 72 00 74 00 6f 00 6e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 65 00 78 00 65 00 } //1 NortonSecurity.exe
		$a_00_1 = {42 00 69 00 74 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 43 00 4f 00 4d 00 2e 00 65 00 78 00 65 00 } //1 BitDefenderCOM.exe
		$a_03_2 = {4c 0f b7 ee 48 8b 4c 24 ?? e8 63 d2 fc ff 48 8b 4c 24 ?? 48 8b 09 0f b7 d7 c1 ea 08 4a 0f b6 4c 29 ff 32 ca 42 88 4c 28 ff 66 42 0f b6 44 2b ff 66 03 c7 66 69 c0 6d ce 66 81 c0 bf 58 89 c7 66 83 c6 01 66 41 83 ee 01 66 45 85 f6 75 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*10) >=12
 
}