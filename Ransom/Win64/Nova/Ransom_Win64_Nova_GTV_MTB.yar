
rule Ransom_Win64_Nova_GTV_MTB{
	meta:
		description = "Ransom:Win64/Nova.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 4d 45 2d 4e 4f 56 41 2e 6d 65 } //1 README-NOVA.me
		$a_01_1 = {79 6f 75 20 75 6e 64 65 72 20 63 6f 6e 74 72 6f 6c 6c 20 62 79 20 4e 6f 76 61 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 you under controll by Nova ransomware
		$a_01_2 = {6e 6f 76 61 5f 65 6e 63 72 79 70 74 6f 72 2e 70 64 62 } //1 nova_encryptor.pdb
		$a_01_3 = {64 6f 20 6e 6f 74 20 74 6f 75 63 68 20 74 68 65 20 66 69 6c 65 73 20 62 65 63 6f 75 73 65 20 77 65 20 63 61 6e 27 74 20 64 65 63 72 79 70 74 20 69 74 20 69 66 20 79 6f 75 20 74 6f 75 63 68 20 69 74 } //1 do not touch the files becouse we can't decrypt it if you touch it
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}