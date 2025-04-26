
rule Virus_Win64_Expiro_PAGJ_MTB{
	meta:
		description = "Virus:Win64/Expiro.PAGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 89 fa 47 8a 14 16 44 88 55 cf 44 0f b6 55 cf 44 8b 4d bc 41 01 f9 45 0f b6 c9 45 31 ca 44 88 55 cf 45 89 fa 44 8a 4d cf 47 88 0c 16 4d 8d 7f 01 eb } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}