
rule Ransom_MSIL_FifiLocker_AMTB{
	meta:
		description = "Ransom:MSIL/FifiLocker!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {66 69 66 69 5f 65 72 72 6f 72 2e 6c 6f 67 } //fifi_error.log  1
		$a_80_1 = {2e 66 69 66 69 } //.fifi  1
		$a_80_2 = {66 69 66 69 5f 6b 65 79 2e 62 69 6e } //fifi_key.bin  1
		$a_80_3 = {47 65 6e 65 72 61 74 65 56 69 63 74 69 6d 49 44 } //GenerateVictimID  1
		$a_80_4 = {46 69 66 69 4c 6f 63 6b 65 72 4d 75 74 65 78 } //FifiLockerMutex  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}