
rule Trojan_Win64_DllInject_HTS_MTB{
	meta:
		description = "Trojan:Win64/DllInject.HTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 41 10 65 48 8b 04 25 30 00 00 00 48 8b 48 60 48 8b 05 ?? ?? ?? ?? 48 89 08 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}