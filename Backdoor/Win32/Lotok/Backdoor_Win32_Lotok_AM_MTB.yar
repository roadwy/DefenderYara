
rule Backdoor_Win32_Lotok_AM_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 18 47 88 44 24 19 c6 44 24 1a 54 c6 44 24 1b 53 88 44 24 1c 88 4c 24 1d c6 44 24 1e 56 88 44 24 1f 88 4c 24 20 c6 44 24 21 32 c6 44 24 22 2e c6 44 24 23 30 88 5c 24 24 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}