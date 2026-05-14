
rule Ransom_MSIL_Encoder_PE_MTB{
	meta:
		description = "Ransom:MSIL/Encoder.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 65 73 74 } //1 files have been encrypted with strongest
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 64 00 61 00 6d 00 61 00 67 00 65 00 64 00 } //1 Your system32 will be damaged
		$a_01_2 = {44 00 4f 00 5f 00 4e 00 4f 00 54 00 5f 00 4f 00 50 00 45 00 4e 00 5f 00 54 00 48 00 45 00 5f 00 46 00 55 00 43 00 4b 00 49 00 4e 00 5f 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 } //3 DO_NOT_OPEN_THE_FUCKIN_RANSOMWARE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}