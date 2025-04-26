
rule Ransom_MSIL_Cryptolocker_PDJ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Files has been encrypted
		$a_81_1 = {68 69 64 64 65 6e 20 74 65 61 72 } //1 hidden tear
		$a_81_2 = {48 41 4e 54 41 } //1 HANTA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Ransom_MSIL_Cryptolocker_PDJ_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 } //1 How To Decrypt My Files
		$a_81_1 = {2e 45 6e 63 72 79 70 74 65 64 } //1 .Encrypted
		$a_81_2 = {59 6f 75 72 20 42 54 43 20 41 64 64 72 65 73 73 } //1 Your BTC Address
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDJ_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6e 65 74 40 73 68 20 40 66 69 72 40 65 77 61 40 6c 6c 20 73 65 40 74 20 6f 70 40 6d 6f 40 64 65 20 64 69 73 40 61 62 6c 65 } //1 net@sh @fir@ewa@ll se@t op@mo@de dis@able
		$a_81_1 = {52 61 6e 73 6f 6d } //1 Ransom
		$a_81_2 = {68 75 72 72 79 20 68 75 72 72 79 20 68 75 72 72 79 } //1 hurry hurry hurry
		$a_81_3 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } //1 GetExtension
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDJ_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your files have been encrypted
		$a_81_1 = {62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //1 bootstatuspolicy ignoreallfailures
		$a_81_2 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 recoveryenabled no
		$a_81_3 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}