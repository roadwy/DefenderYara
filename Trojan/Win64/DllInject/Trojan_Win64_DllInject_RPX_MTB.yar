
rule Trojan_Win64_DllInject_RPX_MTB{
	meta:
		description = "Trojan:Win64/DllInject.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 43 38 2d ?? ?? ?? ?? 09 43 78 8b 43 44 48 8b 8b b8 00 00 00 42 31 04 09 49 83 c1 04 8b 83 cc 00 00 00 01 43 44 8b 4b 40 2b 8b a8 00 00 00 01 8b b0 00 00 00 8b 4b 54 81 e9 ?? ?? ?? ?? 01 8b f8 00 00 00 49 81 f9 ec e2 01 00 7c b3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}