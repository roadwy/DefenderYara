
rule Ransom_MacOS_EvilQuest_B_MTB{
	meta:
		description = "Ransom:MacOS/EvilQuest.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f0 48 8d 05 fb 45 01 00 48 89 bd e8 fe ff ff 48 89 c7 e8 [0-04] 48 8b bd e8 fe ff ff 48 89 c6 e8 [0-04] 48 89 85 30 ff ff ff 48 83 bd 30 ff ff ff 00 0f 84 [0-04] 48 8b bd 30 ff ff ff e8 [0-04] 83 f8 00 0f } //2
		$a_03_1 = {c0 89 c6 48 8b bd 30 ff ff ff ba 02 00 00 00 e8 [0-04] 48 8b bd 30 ff ff ff 89 85 e4 fe ff ff e8 [0-04] 31 c9 89 ce 31 d2 48 89 45 d0 48 8b bd 30 ff ff ff e8 [0-04] 48 83 7d d0 00 0f 87 [0-04] 48 8b bd 30 ff ff ff e8 [0-04] 48 8b bd 30 ff ff ff e8 [0-04] c7 45 fc fd ff ff ff e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}