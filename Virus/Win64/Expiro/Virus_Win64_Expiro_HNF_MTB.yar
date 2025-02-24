
rule Virus_Win64_Expiro_HNF_MTB{
	meta:
		description = "Virus:Win64/Expiro.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 8b 48 20 49 29 fa 4d 2b d1 41 c1 ea 01 44 8b 48 24 4f 01 d1 4b 01 f9 47 8b 11 43 c1 e2 10 41 c1 ea 0e 44 8b 48 1c 4f 01 d1 4c 03 cf 47 8b 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}