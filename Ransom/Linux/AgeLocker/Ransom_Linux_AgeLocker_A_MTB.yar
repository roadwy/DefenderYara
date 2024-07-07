
rule Ransom_Linux_AgeLocker_A_MTB{
	meta:
		description = "Ransom:Linux/AgeLocker.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 6f 70 74 2f 61 67 65 6c 6f 63 6b 65 72 2f 61 67 65 6c 6f 63 6b 65 72 2e 67 6f } //1 /opt/agelocker/agelocker.go
		$a_00_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //1 main.encrypt
		$a_00_2 = {6d 61 69 6e 2e 73 74 6f 70 5f 73 65 72 76 69 63 65 } //1 main.stop_service
		$a_00_3 = {67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 63 72 79 70 74 6f 2f 63 68 61 63 68 61 32 30 } //1 golang.org/x/crypto/chacha20
		$a_00_4 = {6d 61 69 6e 2e 73 74 72 69 6e 67 49 6e 53 6c 69 63 65 } //1 main.stringInSlice
		$a_00_5 = {46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 2e } //1 FILES ARE ENCRYPTED.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}