
rule Trojan_Win64_TrickBot_ARAC_MTB{
	meta:
		description = "Trojan:Win64/TrickBot.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c2 88 44 24 41 0f b7 01 66 89 46 fd 0f b6 41 02 33 c9 88 46 ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}