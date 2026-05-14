
rule TrojanDownloader_MacOS_SAgnt_D_MTB{
	meta:
		description = "TrojanDownloader:MacOS/SAgnt.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 75 b0 48 8d 3d 22 19 00 00 b0 00 e8 6e 03 00 00 48 8d 3d 34 19 00 00 ff 15 3e 17 00 00 48 89 45 a8 48 8b 7d b0 48 8b 55 a8 48 8b 35 53 2c 00 00 b9 01 00 00 00 41 b8 04 00 00 00 31 c0 41 89 c1 ff 15 05 17 00 00 48 8b 75 a8 48 8d 3d 1a 19 00 00 b0 00 e8 26 03 00 00 48 8b 3d e4 2c 00 00 e8 44 03 00 00 48 89 45 a0 48 8b 7d a0 48 8b 35 18 2c 00 00 48 8d 15 11 19 00 00 ff 15 cb 16 00 00 48 8b 45 a0 48 89 85 60 ff ff ff 48 8b 45 a8 48 89 45 f0 } //1
		$a_01_1 = {48 89 85 40 ff ff ff 48 8d 3d 55 23 00 00 ff 15 ff 1f 00 00 48 89 85 38 ff ff ff 48 8b 3d f1 35 00 00 48 8b 95 38 ff ff ff 48 8b 35 6b 35 00 00 ff 15 cd 1f 00 00 48 89 c7 e8 34 0c 00 00 48 89 85 30 ff ff ff 48 83 bd 30 ff ff ff 00 75 18 48 8d 3d 2d 23 00 00 31 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}