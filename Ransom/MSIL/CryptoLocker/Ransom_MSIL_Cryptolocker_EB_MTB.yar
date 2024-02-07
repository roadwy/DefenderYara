
rule Ransom_MSIL_Cryptolocker_EB_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {9a 0b 07 14 72 90 01 03 70 17 8d 03 00 00 01 13 90 01 01 11 90 01 01 16 72 90 01 03 70 a2 11 90 01 01 14 14 14 28 90 01 03 0a 28 90 01 03 0a 2c 02 2b 0b 07 28 90 01 03 0a 28 90 01 03 0a 11 90 01 01 17 d6 13 90 01 01 11 90 01 01 11 90 01 01 8e b7 32 b6 90 00 } //01 00 
		$a_81_1 = {2e 61 72 6d 79 } //01 00  .army
		$a_81_2 = {2e 61 72 73 69 75 6d } //00 00  .arsium
	condition:
		any of ($a_*)
 
}