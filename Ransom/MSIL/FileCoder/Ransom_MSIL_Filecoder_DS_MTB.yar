
rule Ransom_MSIL_Filecoder_DS_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 62 61 63 6b 2e 70 6e 67 } //01 00  ransomback.png
		$a_81_1 = {55 70 64 61 74 65 44 65 63 72 79 70 74 65 72 2e 65 78 65 } //01 00  UpdateDecrypter.exe
		$a_81_2 = {2e 63 72 79 70 74 } //01 00  .crypt
		$a_81_3 = {72 61 6e 73 6f 6d 75 70 64 61 74 65 } //01 00  ransomupdate
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //00 00  DisableTaskMgr
	condition:
		any of ($a_*)
 
}