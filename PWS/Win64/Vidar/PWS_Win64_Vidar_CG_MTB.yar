
rule PWS_Win64_Vidar_CG_MTB{
	meta:
		description = "PWS:Win64/Vidar.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 0c 19 48 ff ca 4c 89 c3 48 85 d2 7c ?? 4c 8d 43 01 44 0f b6 0c 10 4c 39 c6 73 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}