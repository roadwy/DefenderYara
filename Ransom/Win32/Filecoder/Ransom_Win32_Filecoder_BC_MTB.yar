
rule Ransom_Win32_Filecoder_BC_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //02 00 
		$a_81_1 = {46 65 6e 69 78 49 6c 6f 76 65 79 6f 75 21 21 } //02 00 
		$a_81_2 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //01 00 
		$a_81_3 = {43 72 79 70 74 6f 6c 6f 63 6b 65 72 2e 74 78 74 } //01 00 
		$a_81_4 = {48 65 6c 70 20 74 6f 20 64 65 63 72 79 70 74 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}