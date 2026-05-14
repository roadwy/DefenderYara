
rule Trojan_Win64_Orcusrat_BZ_MTB{
	meta:
		description = "Trojan:Win64/Orcusrat.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 54 00 00 00 75 08 66 9d 58 e9 ?? ?? ?? ?? 3d 4c 00 00 00 75 08 66 9d 58 e9 ?? ?? ?? ?? 3d 0f 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}