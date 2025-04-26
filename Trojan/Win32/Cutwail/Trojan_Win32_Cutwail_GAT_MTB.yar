
rule Trojan_Win32_Cutwail_GAT_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0f 01 d9 81 ee ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 21 f1 8b 75 ec 8b 5d c4 8a 34 1e 32 34 0f 8b 4d e8 88 34 19 8b 4d c0 8b 75 f0 39 f1 8b 4d b8 8b 75 c0 8b 7d b0 89 4d dc 89 7d d4 89 75 d8 0f 84 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}