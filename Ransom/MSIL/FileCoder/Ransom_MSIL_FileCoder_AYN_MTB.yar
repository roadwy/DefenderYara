
rule Ransom_MSIL_FileCoder_AYN_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 68 61 63 6b 65 64 20 77 69 74 68 20 74 68 65 20 41 7a 7a 61 53 65 63 20 72 61 6e 73 6f 6d 77 61 72 65 20 76 69 72 75 73 } //2 Your system has been hacked with the AzzaSec ransomware virus
		$a_01_1 = {72 61 6e 73 6f 6d 65 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 7a 7a 61 53 65 63 2e 70 64 62 } //1 ransomeware\obj\Debug\AzzaSec.pdb
		$a_01_2 = {4f 6f 6f 70 73 2c 20 59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //1 Ooops, Your Files Have Been Encrypted
		$a_00_3 = {41 00 7a 00 7a 00 61 00 53 00 65 00 63 00 5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //1 AzzaSec_Encryptor
		$a_01_4 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}