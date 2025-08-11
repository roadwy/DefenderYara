
rule Ransom_MSIL_HiddenTear_ASD_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.ASD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 46 69 6c 65 } //2 EncryptFile
		$a_01_1 = {54 65 73 74 52 61 6e 73 6f 6d } //2 TestRansom
		$a_01_2 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4e 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 20 00 42 00 59 00 20 00 4e 00 41 00 4e 00 4f 00 43 00 52 00 59 00 50 00 54 00 20 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 } //2 YOUR FILES HAVE BEEN ENCRYPTED BY NANOCRYPT RANSOMWARE
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 31 35 31 33 38 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 54 65 73 74 52 61 6e 73 6f 6d 5c 54 65 73 74 52 61 6e 73 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 65 73 74 52 61 6e 73 6f 6d 2e 70 64 62 } //2 C:\Users\15138\source\repos\TestRansom\TestRansom\obj\Debug\TestRansom.pdb
		$a_01_4 = {24 36 38 62 64 64 32 35 38 2d 35 35 39 30 2d 34 66 38 31 2d 61 62 65 32 2d 38 63 64 31 32 32 37 64 37 36 63 62 } //2 $68bdd258-5590-4f81-abe2-8cd1227d76cb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}