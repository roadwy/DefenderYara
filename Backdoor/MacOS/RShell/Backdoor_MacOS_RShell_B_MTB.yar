
rule Backdoor_MacOS_RShell_B_MTB{
	meta:
		description = "Backdoor:MacOS/RShell.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 df e8 95 90 01 03 48 8d 35 87 30 01 00 48 8d bd 50 90 01 03 e8 d6 04 00 00 48 8d 35 25 2f 01 00 48 8d 7d b0 e8 10 ec ff ff 48 89 c3 4c 8d a5 50 90 01 03 4c 89 e7 e8 60 90 01 03 8a 03 41 8a 0c 24 88 0b 41 88 04 24 4c 8d ad 58 90 01 03 48 8b 43 08 49 8b 4d 00 48 89 4b 08 49 89 45 00 48 89 df e8 35 90 01 03 4c 89 e7 e8 2d 90 01 03 41 0f b6 75 f8 4c 89 ef e8 cc f4 ff ff 48 8d 7d c0 e8 c4 ca fe ff 48 8d bd 60 90 01 03 48 8d 75 c0 e8 27 ed ff ff 48 8d 35 ff 2f 01 00 48 8d 7d b0 e8 95 eb ff ff 48 89 c3 4c 8d a5 60 90 01 03 4c 89 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}