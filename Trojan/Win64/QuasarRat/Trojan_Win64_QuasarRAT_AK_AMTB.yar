
rule Trojan_Win64_QuasarRAT_AK_AMTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.AK!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d1 44 69 c1 ?? ?? ?? ?? 41 81 f0 ?? ?? ?? ?? 44 89 44 96 ?? ff c1 83 f9 ?? 7c e4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}