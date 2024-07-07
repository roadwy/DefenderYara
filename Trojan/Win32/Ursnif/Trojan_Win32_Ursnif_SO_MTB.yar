
rule Trojan_Win32_Ursnif_SO_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 74 24 10 81 c7 20 fe 0f 01 8d 54 00 3d 89 3d 90 01 04 89 bc 31 eb f0 ff ff 0f b7 ca 0f b6 15 90 01 04 83 ea 02 74 3b 83 ea 5c 74 2a 83 ea 17 74 14 90 00 } //1
		$a_03_1 = {8d 54 07 ca 8b 3d 90 01 04 89 15 90 01 04 8b bc 37 eb f0 ff ff 0f b7 f1 03 de 8d 04 58 0f b6 1d 90 01 04 8d 84 28 a7 ad ff ff 0f b6 2d 90 01 04 0f af eb 81 fd 6e 81 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}