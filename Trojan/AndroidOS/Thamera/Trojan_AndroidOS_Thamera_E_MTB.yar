
rule Trojan_AndroidOS_Thamera_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 0a a0 13 71 20 1d 2a a9 00 1a 0a 02 1f 71 20 1d 2a a1 00 1a 0a 01 1f 71 20 1d 2a a2 00 62 0a be 09 6e 20 9d 19 9a 00 0c 0a 22 00 49 05 12 03 12 14 70 30 1d 23 30 04 62 03 c2 09 71 20 98 2e 3a 00 0c 04 6e 30 1e 23 30 04 62 03 b7 09 } //5
		$a_01_1 = {c0 c1 13 03 21 00 a5 03 01 03 c2 31 18 03 f5 05 97 79 ed d9 a9 62 9d 01 01 03 13 03 1c 00 a5 03 01 03 c2 31 18 03 b3 35 8c c8 a5 d0 24 cb 9d 01 01 03 13 03 20 00 c5 31 71 20 cf 2e 21 00 0b 01 a5 04 01 03 17 06 ff ff 00 00 c0 64 71 20 cf 2e 21 00 0b 01 13 08 10 00 a5 08 01 08 17 0a 00 00 ff ff c0 a8 c5 3c c2 4c c2 8c 84 cd 71 40 c3 2e 0d 21 0b 01 a5 04 01 03 c0 64 84 4c 23 c4 6a 08 12 05 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}