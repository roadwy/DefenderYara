
rule Trojan_Win64_LummaStealer_CCHG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.CCHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 8b d0 48 8d 4c 24 90 01 01 e8 90 01 04 0f b6 00 48 8b 4c 24 90 01 01 48 8b 94 24 90 01 04 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 4c 24 90 01 01 48 8b 94 24 90 01 04 48 03 d1 48 8b ca 88 01 e9 90 00 } //1
		$a_03_1 = {48 63 04 24 48 8b 4c 24 90 01 01 0f b7 04 41 89 44 24 90 01 01 8b 04 24 99 b9 90 01 04 f7 f9 8b c2 83 c0 90 01 01 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 90 01 01 66 89 04 4a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}