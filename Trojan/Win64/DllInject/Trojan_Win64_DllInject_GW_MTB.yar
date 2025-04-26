
rule Trojan_Win64_DllInject_GW_MTB{
	meta:
		description = "Trojan:Win64/DllInject.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 0a 41 88 01 49 ff c1 41 81 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}