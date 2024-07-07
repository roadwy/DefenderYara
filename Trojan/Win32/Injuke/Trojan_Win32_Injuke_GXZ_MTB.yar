
rule Trojan_Win32_Injuke_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 88 15 90 01 04 0f bf 8d 90 01 04 0f bf 95 90 01 04 33 ca 66 89 0d 90 01 04 8b 85 90 01 04 2d 90 01 04 89 85 90 01 04 0f bf 8d 90 01 04 0f bf 95 90 01 04 23 ca 66 89 8d 90 01 04 0f be 05 90 01 04 0f be 4d 90 01 01 d3 f8 88 45 90 01 01 81 bd 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}