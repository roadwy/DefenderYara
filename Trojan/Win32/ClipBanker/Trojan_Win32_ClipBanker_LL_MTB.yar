
rule Trojan_Win32_ClipBanker_LL_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 f1 43 00 0c 03 c8 89 45 c8 3b c1 74 13 83 60 08 00 83 c0 0c eb f0 a1 28 a0 44 00 8b 4d dc 89 01 c7 45 fc ?? ?? ?? ?? e8 31 00 00 00 80 7d e6 00 75 6d 3b f7 75 39 e8 34 c3 ff ff ff 70 08 57 8b 4d e0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}