
rule TrojanDownloader_O97M_Obfuse_CFZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CFZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 4b 4c 66 61 49 72 42 2c 20 6f 6e 62 6e 2c 20 61 2c 20 69 5a 4d 58 51 58 71 51 2c 20 57 4c 6d 69 5a 69 2c 20 52 6a 47 4f 54 4d 68 46 64 2c 20 67 6c 72 63 41 2c 20 69 } //1 Dim KLfaIrB, onbn, a, iZMXQXqQ, WLmiZi, RjGOTMhFd, glrcA, i
		$a_01_1 = {73 68 64 6a 73 64 20 3d 20 22 6e 65 77 3a 46 39 33 35 44 43 32 32 22 20 2b 20 22 2d 31 43 46 30 2d 31 31 44 22 20 2b 20 22 30 2d 41 44 42 39 2d 30 30 43 22 20 2b 20 22 30 34 46 44 35 38 41 30 42 22 } //1 shdjsd = "new:F935DC22" + "-1CF0-11D" + "0-ADB9-00C" + "04FD58A0B"
		$a_01_2 = {75 4e 41 71 2e 52 75 6e 20 41 32 2c 20 30 } //1 uNAq.Run A2, 0
		$a_01_3 = {57 4c 6d 69 5a 69 20 3d 20 52 69 67 68 74 28 69 5a 4d 58 51 58 71 51 2c 20 31 29 20 26 20 52 6a 47 4f 54 4d 68 46 64 } //1 WLmiZi = Right(iZMXQXqQ, 1) & RjGOTMhFd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}