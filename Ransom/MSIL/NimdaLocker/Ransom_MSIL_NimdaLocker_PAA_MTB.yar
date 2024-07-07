
rule Ransom_MSIL_NimdaLocker_PAA_MTB{
	meta:
		description = "Ransom:MSIL/NimdaLocker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 4e 00 69 00 6d 00 64 00 61 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //5 /c del NimdaLocker.exe
		$a_01_1 = {70 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 61 00 63 00 71 00 75 00 69 00 72 00 65 00 64 00 21 00 } //1 private information have been acquired!
		$a_01_2 = {52 61 6e 73 6f 6d 77 61 72 65 2e 46 75 6e 63 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Ransomware.Functions.resources
		$a_81_3 = {45 6e 63 72 79 70 74 69 6f 6e 20 46 69 6e 69 73 68 65 64 21 } //1 Encryption Finished!
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=7
 
}