
rule Trojan_Win32_ClipBanker_PB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 28 ca 0f 10 41 90 01 01 66 0f ef c8 0f 11 49 90 01 01 0f 28 ca 0f 10 41 90 01 01 66 0f ef 90 01 01 0f 11 90 01 01 b0 90 02 06 0f 10 41 90 01 01 66 0f ef 90 01 01 0f 11 90 02 08 0f 10 41 90 01 01 66 0f ef c8 0f 11 49 90 01 01 83 90 01 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}