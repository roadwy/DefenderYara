
rule Trojan_Win64_Lazy_AMZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 48 8b 4c 24 10 8a 54 24 0f 32 14 01 88 14 01 48 83 c0 01 48 89 44 24 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}