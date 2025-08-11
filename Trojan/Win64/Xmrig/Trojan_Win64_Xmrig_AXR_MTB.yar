
rule Trojan_Win64_Xmrig_AXR_MTB{
	meta:
		description = "Trojan:Win64/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 48 8b 5c 24 48 48 8b 4c 24 30 48 8d 3d c9 e1 07 00 be 18 00 00 00 e8 d9 4e df ff 48 89 44 24 58 48 89 5c 24 40 48 8b 4c 24 30 48 8d 3d b2 cd 07 00 be 16 00 00 00 31 c0 48 8b 5c 24 48 e8 b2 4e df ff 48 89 44 24 50 48 89 5c 24 38 48 89 c1 48 89 df 48 8d 05 b4 44 08 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Xmrig_AXR_MTB_2{
	meta:
		description = "Trojan:Win64/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 48 89 5c 24 40 48 89 5c 24 48 41 b8 15 00 00 00 48 8d 15 5d 6c 04 00 48 8d 4c 24 30 e8 ?? ?? ?? ?? ?? 0f 57 c0 0f 11 44 24 50 48 89 5c 24 60 48 89 5c 24 68 41 b8 16 00 00 00 48 8d 15 4b 6c 04 00 48 8d 4c 24 50 } //3
		$a_03_1 = {0f 57 c0 0f 11 45 d0 48 89 5d e0 48 89 5d e8 41 b8 15 00 00 00 48 8d 15 f8 6b 04 00 48 8d 4d d0 e8 ?? ?? ?? ?? ?? 0f 57 c0 0f 11 45 f0 48 89 5d 00 48 89 5d 08 41 b8 17 00 00 00 48 8d 15 ea 6b 04 00 48 8d 4d f0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}