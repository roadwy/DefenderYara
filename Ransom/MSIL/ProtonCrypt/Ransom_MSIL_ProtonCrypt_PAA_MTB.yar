
rule Ransom_MSIL_ProtonCrypt_PAA_MTB{
	meta:
		description = "Ransom:MSIL/ProtonCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_01_1 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 45 78 } //1 GetComputerNameEx
		$a_01_2 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
		$a_01_3 = {43 6f 6d 70 75 74 65 72 4e 61 6d 65 4e 65 74 42 49 4f 53 } //1 ComputerNameNetBIOS
		$a_01_4 = {43 6f 6d 70 75 74 65 72 4e 61 6d 65 50 68 79 73 69 63 61 6c 4e 65 74 42 49 4f 53 } //1 ComputerNamePhysicalNetBIOS
		$a_01_5 = {43 6f 6d 70 75 74 65 72 4e 61 6d 65 50 68 79 73 69 63 61 6c 44 6e 73 48 6f 73 74 6e 61 6d 65 } //1 ComputerNamePhysicalDnsHostname
		$a_01_6 = {50 72 6f 6a 65 63 74 50 72 6f 74 6f 6e 2e 70 72 6f 74 6f 6e 2e 73 65 72 76 69 63 65 2e 65 78 65 } //1 ProjectProton.proton.service.exe
		$a_81_7 = {57 52 49 54 45 20 27 70 72 6f 74 6f 6e 27 20 54 4f 20 52 55 4e 20 52 41 4e 53 4f 4d 57 41 52 45 } //1 WRITE 'proton' TO RUN RANSOMWARE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}