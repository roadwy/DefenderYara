
rule Trojan_Win32_ClipBanker_NCB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 9f 41 8b 55 ?? 89 45 f8 89 4d ?? eb 03 8b 4d f4 43 8b 04 9f 66 39 30 } //5
		$a_01_1 = {6d 70 64 6d 61 73 6c 73 6f 69 65 } //1 mpdmaslsoie
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}