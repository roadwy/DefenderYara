
rule Trojan_Win32_Ursnif_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 45 f8 8b 00 83 e1 01 c1 e1 03 d3 e0 01 05 90 01 04 ff 4d fc 90 01 02 ff 75 f4 ff 15 90 01 04 ff 75 fc 83 45 f8 04 ff 75 f4 ff 15 90 01 04 3d 02 01 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Ursnif_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d fb 0f b6 45 fb 8b 0d 90 01 04 03 8d 90 01 04 0f be 11 33 d0 a1 38 20 45 00 03 85 90 01 04 88 10 e9 90 01 04 83 3d f8 21 45 00 3e 90 01 02 a1 90 01 04 c6 40 10 46 33 c0 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}