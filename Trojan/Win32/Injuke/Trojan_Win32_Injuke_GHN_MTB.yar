
rule Trojan_Win32_Injuke_GHN_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 33 c2 8b 8d 90 01 04 88 01 8b 95 90 01 04 0f bf 02 99 b9 6d 02 00 00 f7 f9 66 a3 90 01 04 0f bf 95 0c ed ff ff 0f bf 8d 90 01 04 d3 fa 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}