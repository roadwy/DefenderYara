
rule Ransom_MSIL_Filecoder_FF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your important files are encrypted
		$a_81_1 = {62 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 72 65 73 73 } //1 bitcoin to this adress
		$a_81_2 = {43 61 6e 20 69 20 72 65 63 6f 76 65 72 20 6d 79 20 66 69 6c 65 73 3f } //1 Can i recover my files?
		$a_81_3 = {50 61 79 6d 65 6e 74 20 69 73 20 61 63 63 65 70 74 65 64 20 6f 6e 6c 79 20 69 6e 20 62 69 74 63 6f 69 6e } //1 Payment is accepted only in bitcoin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}