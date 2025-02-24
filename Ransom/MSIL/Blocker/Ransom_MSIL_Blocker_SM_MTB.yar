
rule Ransom_MSIL_Blocker_SM_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 14 0a 73 03 00 00 0a 72 01 00 00 70 28 04 00 00 0a 6f 05 00 00 0a 0a 06 0b dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}