
rule TrojanDropper_Win64_WinGo_AMCN_MTB{
	meta:
		description = "TrojanDropper:Win64/WinGo.AMCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 88 54 01 ff 48 ff c6 4c 89 d8 4c 89 e2 48 39 f3 0f 8e ?? ?? ?? ?? 44 0f b6 14 30 48 85 c9 0f 84 ?? ?? ?? ?? 49 89 c3 48 89 f0 49 89 d4 48 99 48 f7 f9 48 39 ca 73 ?? 49 ff c1 42 0f b6 14 22 41 31 d2 4c 39 cf 73 ?? 48 89 74 24 ?? 44 88 54 24 ?? 4c 89 c0 4c 89 cb 48 89 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}