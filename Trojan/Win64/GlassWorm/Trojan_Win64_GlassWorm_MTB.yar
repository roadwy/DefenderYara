
rule Trojan_Win64_GlassWorm_MTB{
	meta:
		description = "Trojan:Win64/GlassWorm!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8b 14 01 48 8b 0c 02 4c 31 d1 4c 21 c1 49 31 ca 4d 89 14 01 48 31 0c 02 48 83 c0 08 48 83 f8 28 75 dd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}