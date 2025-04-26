
rule Trojan_Win64_Emotet_BI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 44 05 ?? 4c 8b 0d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 99 c1 ea ?? 01 d0 83 e0 ?? 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 [0-05] 8b 85 [0-05] 3b 85 [0-05] 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}