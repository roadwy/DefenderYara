
rule Ransom_Win64_ContiCrypt_PF_MTB{
	meta:
		description = "Ransom:Win64/ContiCrypt.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 74 69 5f 76 33 2e 64 6c 6c } //conti_v3.dll  00 00 
	condition:
		any of ($a_*)
 
}