
rule Trojan_Win64_Filecoder_BA_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 72 65 65 74 69 6e 67 73 20 66 72 6f 6d 20 43 73 2d 31 33 37 20 47 72 6f 75 70 } //1 Greetings from Cs-137 Group
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 43 68 61 43 68 61 32 30 } //1 Your files have been encrypted with ChaCha20
		$a_81_2 = {54 68 65 20 65 6e 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 77 61 73 20 72 61 6e 64 6f 6d 6c 79 20 67 65 6e 65 72 61 74 65 64 20 61 6e 64 20 6e 6f 74 20 73 61 76 65 64 20 62 65 63 61 75 73 65 20 74 68 69 73 20 69 73 20 64 65 76 65 6c 6f 70 6d 65 6e 74 20 76 65 72 73 69 6f 6e } //1 The encryption key was randomly generated and not saved because this is development version
		$a_81_3 = {54 68 69 73 20 6d 65 61 6e 73 20 79 6f 75 72 20 66 69 6c 65 73 20 63 61 6e 6e 6f 74 20 62 65 20 72 65 63 6f 76 65 72 65 64 } //1 This means your files cannot be recovered
		$a_81_4 = {47 6f 20 61 77 61 79 20 73 65 63 75 72 69 74 79 20 72 65 73 65 61 72 63 68 2c 2c } //1 Go away security research,,
		$a_81_5 = {75 73 73 61 64 6d 69 6e 2e 65 78 65 20 63 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //1 ussadmin.exe celete shadows /all
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}