
rule Trojan_Win64_LummaC_GTK_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 20 d0 41 88 c2 41 80 f2 ?? 41 80 e2 ?? 20 d0 45 08 c1 41 08 c2 45 30 d1 88 c8 44 20 c8 44 30 c9 08 c8 a8 01 41 be ?? ?? ?? ?? 41 bf ?? ?? ?? ?? 45 0f 45 fe 44 89 7d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}