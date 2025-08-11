
rule Ransom_Win64_PrinceRansom_PA_MTB{
	meta:
		description = "Ransom:Win64/PrinceRansom.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 } //1 Go build ID: "
		$a_01_1 = {2d 52 61 6e 73 6f 6d 77 61 72 65 2f 65 6e 63 72 79 70 74 69 6f 6e 2e 45 6e 63 72 79 70 74 46 69 6c 65 } //1 -Ransomware/encryption.EncryptFile
		$a_03_2 = {2d 6c 64 66 6c 61 67 73 3d 22 2d 48 3d 77 69 6e 64 6f 77 73 67 75 69 20 2d 73 20 2d 77 20 2d 58 20 27 [0-15] 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2e 50 75 62 6c 69 63 4b 65 79 3d } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}