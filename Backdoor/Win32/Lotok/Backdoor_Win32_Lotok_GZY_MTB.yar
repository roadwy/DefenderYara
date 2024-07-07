
rule Backdoor_Win32_Lotok_GZY_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 89 c1 61 31 db b9 90 01 04 ac 60 89 da 89 d1 61 49 32 06 88 07 83 c6 01 83 c7 01 49 85 c9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}