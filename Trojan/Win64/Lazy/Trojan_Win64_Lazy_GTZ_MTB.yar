
rule Trojan_Win64_Lazy_GTZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec ?? 41 81 f1 ?? ?? ?? ?? 48 83 ec ?? 8b f0 41 81 f2 ?? ?? ?? ?? 33 c0 48 83 c0 } //10
		$a_03_1 = {55 48 89 e5 48 83 ec ?? 33 c0 41 81 f0 ?? ?? ?? ?? 41 81 f1 ?? ?? ?? ?? 8b c8 41 81 f2 ?? ?? ?? ?? 48 83 c0 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}