
rule Ransom_MSIL_Hiddentear_DA_MTB{
	meta:
		description = "Ransom:MSIL/Hiddentear.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 69 64 64 65 6e 20 74 65 61 72 } //01 00  hidden tear
		$a_81_1 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //01 00  ransom.jpg
		$a_81_2 = {52 45 41 44 5f 49 54 2e 74 78 74 2e 6c 6f 63 6b 65 64 } //01 00  READ_IT.txt.locked
		$a_81_3 = {68 74 74 70 3a 2f 2f 69 2e 69 6d 67 75 72 2e 63 6f 6d 2f } //00 00  http://i.imgur.com/
	condition:
		any of ($a_*)
 
}