
rule Trojan_Win64_IcedID_GFT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {48 8b 44 24 70 0f bf 00 0f bf 4c 24 44 03 c1 48 8b 4c 24 70 66 89 01 48 8b 44 24 70 0f bf 00 0f bf 0d 90 01 04 33 c1 66 89 44 24 44 0f b6 44 24 40 d1 f8 88 44 24 40 48 8b 44 24 70 0f bf 00 0f bf 0d 90 01 04 0b c1 66 89 44 24 44 0f be 44 24 43 d1 e0 88 44 24 43 90 00 } //10
		$a_80_1 = {48 69 70 70 20 66 69 72 65 62 72 61 6e 20 62 61 74 68 65 20 63 6f 6e 76 6f 6c 75 74 69 6f 20 65 6e 64 75 72 65 } //Hipp firebran bathe convolutio endure  1
		$a_80_2 = {45 6e 67 6f 72 67 20 66 6c 6f 75 } //Engorg flou  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}