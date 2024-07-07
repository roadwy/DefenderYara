
rule Ransom_Win32_Wormhole_YAA_MTB{
	meta:
		description = "Ransom:Win32/Wormhole.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 20 61 6e 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 20 61 6e 64 20 57 6f 72 6d 68 6f 6c 65 20 49 44 } //10 send an encrypted file and Wormhole ID
		$a_03_1 = {8b 0a 33 cb bf ff fe fe 7e 03 f9 83 f1 ff 33 cf 83 c2 04 81 e1 00 01 01 81 74 90 01 01 8b 4a fc 32 cb 74 90 00 } //10
		$a_01_2 = {57 6f 72 6d 68 6f 6c 65 2e 65 78 65 } //1 Wormhole.exe
		$a_01_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_4 = {72 65 63 6f 76 65 72 20 66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 57 6f 72 6d 68 6f 6c 65 2e 74 78 74 } //1 recover files encrypted by Wormhole.txt
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}