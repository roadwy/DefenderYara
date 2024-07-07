
rule TrojanProxy_Win32_Liounkor_A{
	meta:
		description = "TrojanProxy:Win32/Liounkor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 81 3d 90 01 04 38 04 00 00 7c 0c 81 3d 90 01 04 ff ff 00 00 7e 0d ff 15 90 01 04 a3 90 01 04 eb db 90 00 } //1
		$a_01_1 = {99 b9 05 00 00 00 f7 f9 89 55 fc ba 01 00 00 00 85 d2 74 76 eb 09 8b 45 fc 83 c0 01 89 45 fc 83 7d fc 05 7d 42 } //1
		$a_03_2 = {68 b8 22 00 00 e8 90 01 04 66 89 85 06 ed ff ff 8a 0d 90 01 04 88 8d 00 ff ff ff b9 3f 00 00 00 33 c0 8d bd 01 ff ff ff f3 ab 66 ab aa 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}