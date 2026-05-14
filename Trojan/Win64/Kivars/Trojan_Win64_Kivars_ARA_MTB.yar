
rule Trojan_Win64_Kivars_ARA_MTB{
	meta:
		description = "Trojan:Win64/Kivars.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8a c3 41 02 02 32 c1 41 88 02 eb 09 } //2
		$a_01_1 = {41 32 0a 41 02 cb 41 88 0a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}