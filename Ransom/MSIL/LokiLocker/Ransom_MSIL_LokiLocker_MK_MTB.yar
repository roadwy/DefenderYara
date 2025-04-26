
rule Ransom_MSIL_LokiLocker_MK_MTB{
	meta:
		description = "Ransom:MSIL/LokiLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 68 69 73 20 66 69 6c 65 20 61 6e 64 20 61 6c 6c 20 6f 74 68 65 72 20 66 69 6c 65 73 20 69 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 4c 6f 6b 69 20 6c 6f 63 6b 65 72 } //1 This file and all other files in your computer are encrypted by Loki locker
		$a_81_1 = {50 6c 65 61 73 65 20 73 65 6e 64 20 75 73 20 6d 65 73 73 61 67 65 20 74 6f 20 74 68 69 73 20 65 2d 6d 61 69 6c } //1 Please send us message to this e-mail
		$a_81_2 = {57 72 69 74 65 20 74 68 69 73 20 49 44 20 69 6e 20 74 68 65 20 74 69 74 6c 65 20 6f 66 20 79 6f 75 72 20 6d 65 73 73 61 67 65 } //1 Write this ID in the title of your message
		$a_81_3 = {69 6e 66 6f 2e 4c 6f 6b 69 } //1 info.Loki
		$a_81_4 = {6d 73 68 74 61 2e 65 78 65 } //1 mshta.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}