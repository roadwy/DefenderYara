
rule Ransom_MSIL_Filecoder_DI_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //01 00  Rasomware2.0
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_2 = {70 61 73 73 77 6f 72 64 31 32 33 } //01 00  password123
		$a_81_3 = {53 43 5f 52 61 6e 73 6f 6d } //01 00  SC_Ransom
		$a_81_4 = {46 69 6c 65 43 72 79 70 74 65 72 } //00 00  FileCrypter
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DI_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 21 } //01 00  YOUR FILES ARE ENCRYPTED!
		$a_81_1 = {2e 44 75 73 6b } //01 00  .Dusk
		$a_81_2 = {44 6f 20 6e 6f 74 20 77 61 73 74 65 20 79 6f 75 72 20 74 69 6d 65 20 74 72 79 69 6e 67 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 75 73 69 6e 67 20 74 68 69 72 64 20 70 61 72 74 79 20 73 65 72 76 69 63 65 73 21 20 4f 6e 6c 79 20 77 65 20 63 61 6e 20 64 6f 20 74 68 61 74 } //01 00  Do not waste your time trying recover your files using third party services! Only we can do that
		$a_81_3 = {53 65 6e 64 20 24 35 30 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 3a } //01 00  Send $50 to this address:
		$a_81_4 = {63 79 62 65 72 2e 64 75 73 6b 66 6c 79 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //00 00  cyber.duskfly@protonmail.com
	condition:
		any of ($a_*)
 
}