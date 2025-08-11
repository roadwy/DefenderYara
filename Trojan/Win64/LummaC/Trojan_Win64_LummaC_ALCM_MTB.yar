
rule Trojan_Win64_LummaC_ALCM_MTB{
	meta:
		description = "Trojan:Win64/LummaC.ALCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 94 c0 41 0f 95 c3 83 fe 0a 0f 9c c2 83 fe 09 0f 9f c3 20 d8 44 08 db 44 20 da 08 c2 89 d8 30 d0 84 d2 41 bb ?? ?? ?? ?? 45 0f 45 df 84 db 45 0f 45 dc 84 c0 45 0f 44 df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}