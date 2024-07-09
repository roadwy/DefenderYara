
rule Trojan_Win64_SpyLoader_SA_MTB{
	meta:
		description = "Trojan:Win64/SpyLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8a 04 01 41 ff c0 ff ca 30 01 48 ff c1 49 ff c1 44 3b 05 ?? ?? ?? ?? 7c } //1
		$a_03_1 = {8a 07 32 01 48 ff c1 88 04 3a 48 ff c7 80 39 ?? 48 0f 44 cd 80 3f ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}