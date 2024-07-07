
rule Ransom_MSIL_Filecoder_PB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 00 6f 00 76 00 2d 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 gov-ransomware
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 20 61 6e 64 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 77 20 65 6e 63 72 79 70 74 65 64 2e } //1 Your computer has been locked and your files are now encrypted.
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_3 = {53 00 65 00 6e 00 64 00 20 00 79 00 6f 00 75 00 72 00 20 00 42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 73 00 20 00 68 00 65 00 72 00 65 00 } //1 Send your Bitcoins here
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}