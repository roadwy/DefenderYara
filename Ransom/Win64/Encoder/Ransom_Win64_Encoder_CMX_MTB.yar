
rule Ransom_Win64_Encoder_CMX_MTB{
	meta:
		description = "Ransom:Win64/Encoder.CMX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
		$a_01_1 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 76 20 22 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 Windows Defender" /v "DisableAntiSpyware
		$a_01_2 = {64 65 6c 65 74 65 5f 73 65 6c 66 2e 76 62 73 } //1 delete_self.vbs
		$a_01_3 = {75 73 65 20 6f 66 20 64 61 74 61 20 72 65 63 6f 76 65 72 79 } //1 use of data recovery
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}