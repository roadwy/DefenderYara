
rule Trojan_Win64_DonutLoader_BG_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 0f b6 0c 0a 45 89 c2 41 83 f2 ff 44 89 ca 44 21 d2 41 83 f1 ff 45 21 c8 44 09 c2 48 8b 00 48 8b 09 88 14 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}