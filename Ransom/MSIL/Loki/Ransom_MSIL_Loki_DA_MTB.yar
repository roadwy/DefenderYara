
rule Ransom_MSIL_Loki_DA_MTB{
	meta:
		description = "Ransom:MSIL/Loki.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files are encrypted
		$a_81_1 = {48 6f 77 54 6f 44 65 63 72 79 70 74 2e 74 78 74 } //01 00  HowToDecrypt.txt
		$a_81_2 = {43 72 65 64 69 74 5f 43 61 72 64 73 2e 6c 6f 67 } //01 00  Credit_Cards.log
		$a_81_3 = {2e 6c 6f 6b 69 } //00 00  .loki
	condition:
		any of ($a_*)
 
}