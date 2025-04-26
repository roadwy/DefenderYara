
rule Trojan_Win64_DllInject_GF_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 15 20 44 31 c8 41 88 00 83 45 74 01 8b 45 74 3b 45 54 72 9a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}