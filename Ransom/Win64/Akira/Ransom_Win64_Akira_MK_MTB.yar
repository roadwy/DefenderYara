
rule Ransom_Win64_Akira_MK_MTB{
	meta:
		description = "Ransom:Win64/Akira.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 20 65 6e 63 72 79 70 74 20 69 6e 66 6f 20 66 72 6f 6d 20 66 69 6c 65 20 66 61 69 6c 65 64 } //10 Read encrypt info from file failed
		$a_01_1 = {28 50 61 72 74 29 20 44 65 63 72 79 70 74 20 65 78 63 65 70 74 69 6f 6e 3a } //10 (Part) Decrypt exception:
		$a_01_2 = {4e 75 6d 62 65 72 20 6f 66 20 74 68 72 65 61 64 73 20 74 6f 20 64 65 63 72 79 70 74 20 3d } //10 Number of threads to decrypt =
		$a_01_3 = {66 69 6c 65 20 72 65 6e 61 6d 65 20 66 61 69 6c 65 64 2e 20 53 79 73 74 65 6d 20 65 72 72 6f 72 3a } //10 file rename failed. System error:
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=35
 
}