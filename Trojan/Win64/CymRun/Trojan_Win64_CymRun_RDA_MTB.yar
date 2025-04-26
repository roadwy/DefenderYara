
rule Trojan_Win64_CymRun_RDA_MTB{
	meta:
		description = "Trojan:Win64/CymRun.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 69 6e 69 73 68 65 64 20 65 6e 63 72 79 70 74 69 6e 67 20 61 6c 6c 20 66 69 6c 65 73 20 28 25 64 20 6f 75 74 20 6f 66 20 25 64 29 2c 20 67 65 74 74 69 6e 67 20 65 76 69 64 65 6e 63 65 } //1 Finished encrypting all files (%d out of %d), getting evidence
		$a_01_1 = {4f 76 65 72 61 6c 6c 20 66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 20 25 64 } //1 Overall files to encrypt %d
		$a_01_2 = {4d 69 73 73 69 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 20 61 72 67 75 6d 65 6e 74 } //1 Missing encryption_path argument
		$a_01_3 = {55 73 69 6e 67 20 64 65 66 61 75 6c 74 20 63 6e 63 20 75 72 6c } //1 Using default cnc url
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}