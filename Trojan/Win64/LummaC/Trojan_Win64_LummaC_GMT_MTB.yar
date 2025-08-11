
rule Trojan_Win64_LummaC_GMT_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 30 c1 44 08 c2 80 f2 ?? 08 ca 41 89 d0 41 30 d8 84 d2 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 0f 45 ca 84 db 0f 44 ca 48 89 44 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}