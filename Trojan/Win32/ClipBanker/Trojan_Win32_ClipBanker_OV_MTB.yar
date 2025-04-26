
rule Trojan_Win32_ClipBanker_OV_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.OV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 8c 35 fc fe ff ff 03 ca 81 e1 ff 00 00 80 79 ?? 49 81 c9 ?? ?? ?? ?? 41 0f b6 84 0d fc fe ff ff 8b 8d f8 fe ff ff 43 30 44 19 ff 3b 5d 0c 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}