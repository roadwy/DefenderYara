
rule Ransom_MSIL_Blocker_SPFV_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.SPFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 1e 11 0a 6f 90 01 03 0a 13 22 11 0d 11 22 11 11 59 61 13 0d 11 11 11 0d 19 58 1e 63 59 13 11 11 0a 6f 90 01 03 06 2d d9 de 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}