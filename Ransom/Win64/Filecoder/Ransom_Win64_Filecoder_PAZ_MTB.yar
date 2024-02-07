
rule Ransom_Win64_Filecoder_PAZ_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  files have been encrypted
		$a_01_1 = {70 61 79 20 61 20 72 61 6e 73 6f 6d } //01 00  pay a ransom
		$a_01_2 = {70 61 79 6d 65 6e 74 } //01 00  payment
		$a_01_3 = {73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //01 00  shadowcopy delete
		$a_01_4 = {21 00 52 00 45 00 53 00 54 00 4f 00 52 00 45 00 21 00 2e 00 74 00 78 00 74 00 } //00 00  !RESTORE!.txt
	condition:
		any of ($a_*)
 
}