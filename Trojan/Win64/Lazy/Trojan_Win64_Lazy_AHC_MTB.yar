
rule Trojan_Win64_Lazy_AHC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 ff c0 48 31 c2 48 8d 05 ?? ?? ?? 00 48 c7 00 00 00 00 00 48 01 38 48 8d 05 ?? ?? ?? 00 48 c7 00 00 00 00 00 4c 01 38 48 89 d0 48 8d 05 ?? ?? ?? 00 48 89 28 48 01 c2 48 31 c0 } //3
		$a_03_1 = {48 31 c2 48 31 c2 48 8d 05 ?? ?? 02 00 48 c7 00 00 00 00 00 48 01 18 48 29 c2 48 83 f2 09 48 8d 05 ?? ?? 02 00 4c 89 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}