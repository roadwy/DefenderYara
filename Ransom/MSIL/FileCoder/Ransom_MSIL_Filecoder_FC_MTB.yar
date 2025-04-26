
rule Ransom_MSIL_Filecoder_FC_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 2e 65 78 65 } //1 Rasomware2.0.exe
		$a_81_1 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 52 61 6e 73 6f 6d 77 61 72 65 32 2e 72 65 73 6f 75 72 63 65 73 } //1 Rasomware2._0.Ransomware2.resources
		$a_81_2 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Rasomware2._0.Properties.Resources.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}