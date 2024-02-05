
rule Trojan_Win32_ClipBanker_MF_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 44 25 00 c0 fa 61 b1 06 8a 4d 04 0f ab fa 80 f2 90 66 0f ba f2 86 81 c5 06 00 00 00 66 0f bd d4 80 e2 0e 36 88 08 66 0f b6 d5 66 c1 da 43 d2 f2 8b 16 e9 } //00 00 
	condition:
		any of ($a_*)
 
}