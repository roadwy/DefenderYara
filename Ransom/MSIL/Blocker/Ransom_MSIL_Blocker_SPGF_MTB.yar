
rule Ransom_MSIL_Blocker_SPGF_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.SPGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 11 04 16 25 2d 1b 32 08 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 1c 2c fb 1c 2c f8 07 6f ?? 00 00 0a 32 cc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}