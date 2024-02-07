
rule Trojan_Win64_BazarLoader_DW_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 c0 07 48 8d 52 01 0f be c9 33 c1 0f b6 0a 84 c9 } //03 00 
		$a_81_1 = {75 72 6d 66 78 6e 6f 79 73 6d 2e 64 6c 6c } //03 00  urmfxnoysm.dll
		$a_81_2 = {61 78 75 73 72 74 62 67 64 } //03 00  axusrtbgd
		$a_81_3 = {62 71 7a 76 61 72 76 74 71 6b 61 71 78 71 } //00 00  bqzvarvtqkaqxq
	condition:
		any of ($a_*)
 
}