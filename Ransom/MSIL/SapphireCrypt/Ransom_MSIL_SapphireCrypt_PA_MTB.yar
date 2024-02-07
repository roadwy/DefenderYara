
rule Ransom_MSIL_SapphireCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/SapphireCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 70 70 68 69 72 65 5f 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  Sapphire_Ransomware
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  cmd /c vssadmin delete shadows /all /quiet
		$a_01_2 = {2e 00 66 00 62 00 69 00 } //01 00  .fbi
		$a_01_3 = {5c 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 42 00 59 00 46 00 42 00 49 00 2e 00 68 00 74 00 61 00 } //00 00  \LOCKEDBYFBI.hta
	condition:
		any of ($a_*)
 
}