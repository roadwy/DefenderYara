
rule Trojan_Win32_GhostSocks_MKV_MTB{
	meta:
		description = "Trojan:Win32/GhostSocks.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d8 0f b6 c0 33 54 85 ?? 8b 5c 24 18 88 14 3b 47 8b 54 24 24 8b 4c 24 28 0f b6 44 24 0f 0f b6 74 24 0e 39 f9 7f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}