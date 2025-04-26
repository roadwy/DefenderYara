
rule Trojan_Win64_ZLoader_DB_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e6 04 01 ce 89 f9 29 f1 48 63 c9 46 0f b6 1c 01 44 32 1c 38 44 88 1c 3a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}