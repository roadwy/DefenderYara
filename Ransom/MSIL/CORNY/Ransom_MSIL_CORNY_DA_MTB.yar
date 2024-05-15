
rule Ransom_MSIL_CORNY_DA_MTB{
	meta:
		description = "Ransom:MSIL/CORNY.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //0a 00  Ransom.Form1.resources
		$a_81_1 = {52 61 6e 73 6f 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Ransom.Properties.Resources
		$a_81_2 = {66 69 6c 65 45 6e 63 72 79 70 74 65 64 } //01 00  fileEncrypted
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {47 65 74 44 72 69 76 65 73 } //01 00  GetDrives
		$a_81_5 = {2e 72 6f 6f 74 } //00 00  .root
	condition:
		any of ($a_*)
 
}