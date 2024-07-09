
rule Trojan_Win32_ClipBanker_DA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 94 11 [0-04] 33 c2 8b 4d ?? 8b 91 [0-04] 8b 4d ?? 88 04 0a e9 } //2
		$a_03_1 = {0f b6 8c 0e [0-04] 33 ca 8b 55 ?? 88 8c 02 [0-04] e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}