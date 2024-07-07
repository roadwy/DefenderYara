
rule Ransom_Win64_Gocoder_A_MSR{
	meta:
		description = "Ransom:Win64/Gocoder.A!MSR,SIGNATURE_TYPE_PEHSTR,03 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 21 20 59 6f 75 72 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 6f 6e 6c 79 20 49 20 63 61 6e 20 64 65 63 72 79 70 74 20 74 68 65 6d } //1 Hello! Your all your files are encrypted and only I can decrypt them
		$a_01_1 = {68 6f 75 72 73 20 74 68 65 6e 20 79 6f 75 72 20 64 61 74 61 20 6d 61 79 20 62 65 20 6c 6f 73 74 20 70 65 72 6d 61 6e 65 6e 74 6c 79 } //1 hours then your data may be lost permanently
		$a_01_2 = {44 6f 20 6e 6f 74 20 74 75 72 6e 20 6f 66 66 20 6f 72 20 72 65 73 74 61 72 74 20 74 68 65 20 4e 41 53 20 65 71 75 69 70 6d 65 6e 74 2e 20 54 68 69 73 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 64 61 74 61 20 6c 6f 73 73 } //1 Do not turn off or restart the NAS equipment. This will result in data loss
		$a_01_3 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 2c 20 62 65 63 61 75 73 65 20 6f 66 20 74 68 69 73 20 79 6f 75 20 63 61 6e 20 6c 6f 73 65 20 74 68 65 6d 20 66 6f 72 65 76 65 72 21 } //1 Do not rename the encrypted files, because of this you can lose them forever!
		$a_01_4 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 66 69 6c 65 2e 66 75 6e 63 31 } //1 main.encryptfile.func1
		$a_01_5 = {6d 61 69 6e 2e 6d 61 6b 65 52 65 61 64 6d 65 46 69 6c 65 2e 66 75 6e 63 31 } //1 main.makeReadmeFile.func1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}