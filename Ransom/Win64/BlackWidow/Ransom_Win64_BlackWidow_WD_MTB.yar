
rule Ransom_Win64_BlackWidow_WD_MTB{
	meta:
		description = "Ransom:Win64/BlackWidow.WD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 34 08 55 48 ff c0 48 83 f8 0c 72 f3 } //1
		$a_81_1 = {50 61 79 6c 6f 61 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 65 78 74 72 61 63 74 65 64 } //1 Payload successfully extracted
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}