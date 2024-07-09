
rule Backdoor_Win64_Mozaakai_ZX_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 00 48 ff c2 49 ff c8 48 3b d7 88 44 32 [0-01] 7c ee } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}