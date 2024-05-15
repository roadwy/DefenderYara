
rule Ransom_Win64_FileCoder_ZC_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 61 6c 77 61 72 65 48 75 6e 74 65 72 54 65 61 6d 20 6d 61 6c 77 72 68 75 6e 74 65 72 74 65 61 6d 20 52 61 6e 73 6f 6d 77 61 72 65 } //0a 00  MalwareHunterTeam malwrhunterteam Ransomware
		$a_01_1 = {47 50 54 4c 6f 63 6b 65 72 } //01 00  GPTLocker
		$a_01_2 = {43 6f 6d 70 6f 6e 65 6e 74 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00  ComponentResourceManager
		$a_01_3 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //01 00  set_UseMachineKeyStore
		$a_01_4 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_01_5 = {67 65 74 5f 41 6c 6c 6f 77 4f 6e 6c 79 46 69 70 73 41 6c 67 6f 72 69 74 68 6d 73 } //01 00  get_AllowOnlyFipsAlgorithms
		$a_01_6 = {41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  AesCryptoServiceProvider
		$a_01_7 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_8 = {42 69 6e 61 72 79 52 65 61 64 65 72 } //01 00  BinaryReader
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}