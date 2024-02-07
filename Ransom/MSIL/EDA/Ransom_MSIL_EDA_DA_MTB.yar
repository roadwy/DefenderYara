
rule Ransom_MSIL_EDA_DA_MTB{
	meta:
		description = "Ransom:MSIL/EDA.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //01 00  ransom.jpg
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 5c 65 64 61 32 5c 65 64 61 32 2d 6d 61 73 74 65 72 } //01 00  Ransomware\eda2\eda2-master
		$a_81_2 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //01 00  bytesToBeEncrypted
		$a_81_3 = {61 65 73 65 6e 63 72 79 70 74 65 64 } //00 00  aesencrypted
	condition:
		any of ($a_*)
 
}