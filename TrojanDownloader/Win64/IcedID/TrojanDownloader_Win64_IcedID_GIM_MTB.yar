
rule TrojanDownloader_Win64_IcedID_GIM_MTB{
	meta:
		description = "TrojanDownloader:Win64/IcedID.GIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 94 24 80 00 00 00 ff ca 48 2b f7 8b cb 8b c3 83 e0 01 d1 e9 03 c0 83 e1 01 0b c8 8b c3 25 fc ff 00 00 ff c3 0b c8 8b c2 83 c1 0f 48 23 c8 42 8a 04 31 32 04 3e 88 07 48 ff c7 3b dd 72 cd } //10
		$a_01_1 = {8a 53 01 c0 e2 03 8a 0b 80 e1 07 0a d1 c0 e2 03 8a 43 ff 24 07 0a d0 43 88 14 08 4c 03 c7 48 8d 5b 03 49 81 f8 00 04 00 00 0f 8d 98 00 00 00 4c 8b 0d 57 bb 01 00 eb c8 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}