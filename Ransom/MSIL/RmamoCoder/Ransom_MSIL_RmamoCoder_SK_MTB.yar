
rule Ransom_MSIL_RmamoCoder_SK_MTB{
	meta:
		description = "Ransom:MSIL/RmamoCoder.SK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5f 52 4d 41 4d 4f 5c 5f 52 4d 41 4d 4f 5c 6f 62 6a 5c 44 65 62 75 67 5c 5f 52 4d 41 4d 4f 2e 70 64 62 } //01 00 
		$a_01_1 = {2e 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00 
		$a_01_2 = {5c 00 50 00 61 00 73 00 73 00 7a 00 2e 00 74 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}