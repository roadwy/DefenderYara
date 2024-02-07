
rule Ransom_MSIL_Filecoder_ER_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {6c 6f 63 6b 65 64 2e 7a 69 70 } //01 00  locked.zip
		$a_81_1 = {74 65 73 74 2e 74 78 74 } //01 00  test.txt
		$a_81_2 = {49 6f 6e 69 63 2e 5a 6c 69 62 } //01 00  Ionic.Zlib
		$a_81_3 = {42 75 69 6c 64 2e 65 78 65 } //01 00  Build.exe
		$a_81_4 = {73 65 74 5f 45 6e 63 72 79 70 74 69 6f 6e } //00 00  set_Encryption
	condition:
		any of ($a_*)
 
}