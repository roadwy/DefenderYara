
rule Ransom_MSIL_HiddenTear_DD_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //01 00  ALL YOUR FILES ARE ENCRYPTED
		$a_81_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 61 20 76 69 72 75 73 } //01 00  Your computer is infected with a virus
		$a_81_2 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //01 00  @tutanota.com
		$a_81_3 = {2e 69 6e 66 6f 2e 68 74 61 } //00 00  .info.hta
	condition:
		any of ($a_*)
 
}