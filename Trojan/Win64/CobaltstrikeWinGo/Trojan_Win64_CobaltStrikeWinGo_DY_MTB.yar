
rule Trojan_Win64_CobaltStrikeWinGo_DY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeWinGo.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 88 4c 30 ff 48 ff c1 4c 89 c7 48 39 cb 7e ?? 4c 8d 47 01 44 0f b6 0c 08 44 0f b6 54 24 ?? 45 31 ca 44 0f b6 4c 24 ?? 45 31 d1 4c 39 c2 73 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}