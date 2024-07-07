
rule Trojan_Win32_Dynamer_GTH_MTB{
	meta:
		description = "Trojan:Win32/Dynamer.GTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 03 d8 81 e3 90 01 04 0f b6 84 1d 90 01 04 88 84 35 90 01 04 88 94 1d 90 01 04 0f b6 8c 35 90 01 04 0f b6 c2 03 c8 81 e1 90 01 04 0f b6 84 0d 90 01 04 8b 4d f8 30 04 0f 47 3b 7d fc 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}