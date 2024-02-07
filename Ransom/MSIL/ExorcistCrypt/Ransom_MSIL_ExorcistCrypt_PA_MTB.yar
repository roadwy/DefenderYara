
rule Ransom_MSIL_ExorcistCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/ExorcistCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //01 00  DisableTaskMgr
		$a_01_1 = {52 00 61 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 32 00 2e 00 30 00 } //01 00  Rasomware2.0
		$a_01_2 = {41 00 4e 00 4e 00 41 00 42 00 45 00 4c 00 4c 00 45 00 20 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 57 00 41 00 52 00 45 00 } //01 00  ANNABELLE RANSOMWARE
		$a_03_3 = {5c 65 78 6f 72 63 69 73 74 5c 65 78 6f 72 63 69 73 74 5c 90 02 10 5c 90 02 10 5c 65 78 6f 72 63 69 73 74 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}