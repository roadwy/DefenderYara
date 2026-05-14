
rule Trojan_Win64_Rozena_YAI_MTB{
	meta:
		description = "Trojan:Win64/Rozena.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 10 8b 45 20 41 89 c0 8b 45 fc 48 63 c8 48 8b 45 10 48 01 c8 44 31 c2 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}