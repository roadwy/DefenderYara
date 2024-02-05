
rule Trojan_Win32_ClipBanker_DA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 94 11 90 02 04 33 c2 8b 4d 90 01 01 8b 91 90 02 04 8b 4d 90 01 01 88 04 0a e9 90 00 } //02 00 
		$a_03_1 = {0f b6 8c 0e 90 02 04 33 ca 8b 55 90 01 01 88 8c 02 90 02 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}