
rule Ransom_MSIL_Filecoder_FI_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 46 75 63 6b 52 61 6e 73 6f 6d } //02 00  SystemFuckRansom
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_81_2 = {41 6c 6c 20 79 6f 75 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All you important files are encrypted
		$a_81_3 = {4e 69 72 6f 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Niros.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}