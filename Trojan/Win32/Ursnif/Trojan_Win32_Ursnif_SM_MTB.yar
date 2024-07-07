
rule Trojan_Win32_Ursnif_SM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 ca 8d 8c 0f de d4 ff ff 89 0d 90 01 04 05 c0 24 60 01 a3 90 01 04 89 06 8b 3d 90 01 04 8d 42 b2 66 39 15 90 00 } //1
		$a_03_1 = {2b c2 2d d1 57 00 00 66 a3 90 01 04 8b c7 2b c1 83 c0 19 2b ca a3 90 01 04 a1 44 96 46 00 49 8d b4 28 2e f5 ff ff 8b 06 49 83 eb 04 74 33 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}