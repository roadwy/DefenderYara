
rule Trojan_Win64_GlassWorm_AGL_MTB{
	meta:
		description = "Trojan:Win64/GlassWorm.AGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 f6 eb 07 40 88 3c 31 48 ff c6 48 39 f3 7e 0e 0f b6 3c 30 31 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}