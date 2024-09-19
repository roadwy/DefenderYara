
rule Trojan_Win64_TinplateLoader_B_dha{
	meta:
		description = "Trojan:Win64/TinplateLoader.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {7b 7d 6e 6a c7 84 24 ?? ?? ?? ?? 34 35 6b 64 c7 84 24 ?? ?? ?? ?? 61 64 61 30 c7 84 24 ?? ?? ?? ?? 73 6c 66 6b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}