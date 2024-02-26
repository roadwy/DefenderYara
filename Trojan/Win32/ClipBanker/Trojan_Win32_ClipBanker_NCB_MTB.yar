
rule Trojan_Win32_ClipBanker_NCB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 04 9f 41 8b 55 90 01 01 89 45 f8 89 4d 90 01 01 eb 03 8b 4d f4 43 8b 04 9f 66 39 30 90 00 } //01 00 
		$a_01_1 = {6d 70 64 6d 61 73 6c 73 6f 69 65 } //00 00  mpdmaslsoie
	condition:
		any of ($a_*)
 
}