
rule Trojan_Win64_DuckTail_GTM_MTB{
	meta:
		description = "Trojan:Win64/DuckTail.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 50 00 60 0a 00 00 2e 69 64 61 ?? 61 24 35 00 00 00 00 60 ?? 50 00 38 00 00 00 2e 30 30 63 66 ?? 00 00 98 2a 50 ?? 08 00 00 00 2e 43 52 54 24 58 } //10
		$a_01_1 = {41 50 45 58 5f 4e 4f 57 41 58 5f 4c 4f 41 44 45 52 } //1 APEX_NOWAX_LOADER
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}