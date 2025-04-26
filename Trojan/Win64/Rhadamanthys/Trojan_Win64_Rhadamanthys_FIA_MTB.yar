
rule Trojan_Win64_Rhadamanthys_FIA_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.FIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 89 44 24 50 48 8b 44 24 40 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 88 44 24 24 0f b6 44 24 24 33 44 24 50 48 8b 4c 24 40 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}