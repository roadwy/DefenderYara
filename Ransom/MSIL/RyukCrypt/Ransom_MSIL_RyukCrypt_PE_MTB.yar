
rule Ransom_MSIL_RyukCrypt_PE_MTB{
	meta:
		description = "Ransom:MSIL/RyukCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 4d 75 74 65 78 52 75 6e } //1 appMutexRun
		$a_81_1 = {3c 45 6e 63 79 70 74 65 64 4b 65 79 3e } //1 <EncyptedKey>
		$a_81_2 = {5c 72 65 61 64 5f 69 74 2e 74 78 74 } //1 \read_it.txt
		$a_81_3 = {72 61 6e 73 6f 6d 77 61 72 65 20 76 69 72 75 73 } //1 ransomware virus
		$a_81_4 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All of your files have been encrypted
		$a_00_5 = {72 00 79 00 75 00 6b 00 2e 00 65 00 78 00 65 00 } //1 ryuk.exe
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}